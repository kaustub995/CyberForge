"""
services/app_auth.py - Authentication management for CyberForge AI Phishing Shield.

Provides:
  - PBKDF2 password hashing & verification in format:
    pbkdf2:sha256:100000$<salt_hex>$<hash_hex>
  - Local admin credential validation with timing-attack prevention
  - Google OIDC configuration detection & graceful fallback
  - Unified session authentication status check & logout handler
"""

from collections.abc import Mapping
import hashlib
import hmac
import os
import streamlit as st

DEFAULT_ADMIN_USERNAME = "admin"
# Default PBKDF2 hash for initial fallback (password: CyberForgeAdmin2026!)
_DEFAULT_ADMIN_SALT_HEX = "4f62e88a9117b9c32d4e5f6a7b8c9d0e"
_DEFAULT_ADMIN_KEY_HEX = hashlib.pbkdf2_hmac(
    "sha256",
    "CyberForgeAdmin2026!".encode("utf-8"),
    bytes.fromhex(_DEFAULT_ADMIN_SALT_HEX),
    100000
).hex()
DEFAULT_ADMIN_PASSWORD_HASH = f"pbkdf2:sha256:100000${_DEFAULT_ADMIN_SALT_HEX}${_DEFAULT_ADMIN_KEY_HEX}"


def hash_password(password: str, salt: bytes = None, iterations: int = 100000) -> str:
    """
    Hash a plaintext password using PBKDF2 with SHA-256.
    Returns string in format: pbkdf2:sha256:100000$<salt_hex>$<hash_hex>
    """
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2:sha256:{iterations}${salt.hex()}${key.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """
    Verify a plaintext password against a PBKDF2 formatted string.
    Expected format: pbkdf2:sha256:<iterations>$<salt_hex>$<hash_hex>
    """
    if not encoded or not isinstance(encoded, str):
        return False
    try:
        parts = encoded.split("$")
        if len(parts) != 3:
            return False
        header, salt_hex, key_hex = parts
        h_parts = header.split(":")
        if len(h_parts) != 3 or h_parts[0] != "pbkdf2" or h_parts[1] != "sha256":
            return False
        iterations = int(h_parts[2])
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        actual_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(expected_key, actual_key)
    except Exception:
        return False


def get_admin_credentials() -> tuple[str, str]:
    """Read ADMIN_USERNAME and ADMIN_PASSWORD_HASH from env/secrets or default."""
    username = (os.getenv("ADMIN_USERNAME") or "").strip()
    if not username and hasattr(st, "secrets"):
        try:
            username = str(st.secrets.get("ADMIN_USERNAME", "")).strip()
        except Exception:
            pass
    if not username:
        username = DEFAULT_ADMIN_USERNAME

    password_hash = (os.getenv("ADMIN_PASSWORD_HASH") or "").strip()
    if not password_hash and hasattr(st, "secrets"):
        try:
            password_hash = str(st.secrets.get("ADMIN_PASSWORD_HASH", "")).strip()
        except Exception:
            pass
    if not password_hash:
        password_hash = DEFAULT_ADMIN_PASSWORD_HASH

    return username, password_hash


def verify_admin_login(username_input: str, password_input: str) -> bool:
    """Validate submitted username and password against configured admin credentials."""
    expected_username, expected_hash = get_admin_credentials()
    user_ok = hmac.compare_digest(
        (username_input or "").strip().lower(),
        expected_username.lower()
    )
    pass_ok = verify_password(password_input or "", expected_hash)
    return user_ok and pass_ok


def has_google_auth_config() -> bool:
    """Check if Streamlit secrets contain complete Google OIDC [auth] configuration."""
    try:
        if not hasattr(st, "secrets"):
            return False
        auth_sec = st.secrets.get("auth")
        if not auth_sec or not isinstance(auth_sec, (dict, Mapping)):
            return False
        client_id = auth_sec.get("client_id")
        client_secret = auth_sec.get("client_secret")
        return bool(client_id and client_secret and str(client_id).strip() and str(client_secret).strip())
    except Exception:
        return False


def is_user_authenticated() -> bool:
    """
    Check if current session is authenticated via Google OIDC or Local Admin.
    """
    # 1. Google OIDC Native check
    try:
        if hasattr(st, "user") and getattr(st.user, "is_logged_in", False):
            return True
    except Exception:
        pass

    # 2. Local Admin session check
    if st.session_state.get("authenticated_admin", False):
        return True

    return False


def get_authenticated_user_info() -> dict:
    """Return dict of current authenticated user details."""
    try:
        if hasattr(st, "user") and getattr(st.user, "is_logged_in", False):
            return {
                "type": "google",
                "name": getattr(st.user, "name", "Google User") or "Google User",
                "email": getattr(st.user, "email", "authenticated@google.com") or "authenticated@google.com",
            }
    except Exception:
        pass

    if st.session_state.get("authenticated_admin", False):
        admin_user = st.session_state.get("admin_user", DEFAULT_ADMIN_USERNAME)
        return {
            "type": "admin",
            "name": f"Admin ({admin_user})",
            "email": f"{admin_user}@cyberforge.local",
        }

    return {"type": "anonymous", "name": "Guest", "email": ""}


def logout_user():
    """Perform logout for Google or Local Admin session."""
    # If Google User:
    try:
        if hasattr(st, "user") and getattr(st.user, "is_logged_in", False):
            st.logout()
            return
    except Exception:
        pass

    # Local Admin logout:
    st.session_state["authenticated_admin"] = False
    st.session_state["admin_user"] = None
    st.rerun()
