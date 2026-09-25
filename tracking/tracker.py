"""
tracking/tracker.py - Token minting, request enrichment and event storage.

Sends a tracked URL to a monitored recipient; the moment they render the
pixel (GET /track/<token>/pixel.gif) or click a link (GET /redir/<token>?u=...)
their real, current IP is observed at interaction time - which closes exactly
the "we only see the datacenter" blind spot of pure header analysis.
"""

import json
import os
import re
import socket
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
import uuid

PIXEL_GIF = (
    b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00"
    b"\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00"
    b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
)


def _db_path() -> str:
    return os.getenv("TRACKING_DB_PATH") or os.getenv("CASE_STORE_PATH") or "data/cases.db"


def _real_ip(ip_or_empty: str) -> str:
    ip = (ip_or_empty or "").strip()
    if ip in ("", "127.0.0.1", "::1"):
        return ""
    return ip


class TrackerStore:
    """Persistent token + interaction-event store (SQLite, thread-safe)."""

    def __init__(self, path=None):
        self.path = path or _db_path()
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def _init_schema(self):
        with self._lock:
            conn = sqlite3.connect(self.path)
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS tracking_tokens ("
                    " token TEXT PRIMARY KEY,"
                    " email_id TEXT,"
                    " campaign_id TEXT,"
                    " created_at REAL)"
                )
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS tracking_events ("
                    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    " token TEXT,"
                    " kind TEXT,"
                    " ip TEXT,"
                    " user_agent TEXT,"
                    " referer TEXT,"
                    " enrichment TEXT,"
                    " created_at REAL)")
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_token "
                    "ON tracking_events(token)")
                conn.commit()
            finally:
                conn.close()

    def mint(self, email_id: str = "", campaign_id: str = "") -> str:
        token = uuid.uuid4().hex
        with self._lock:
            self._conn.execute(
                "INSERT INTO tracking_tokens (token, email_id, campaign_id, created_at)"
                " VALUES (?, ?, ?, ?)",
                (token, email_id, campaign_id, time.time()))
            self._conn.commit()
        return token

    def get(self, token: str):
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM tracking_tokens WHERE token=?", (token,))
            row = cur.fetchone()
        return dict(row) if row else None

    def tokens(self) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tracking_tokens ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
        return [dict(r) for r in rows]

    def log_event(self, token, kind, ip="", user_agent="", referer="", enrichment=None):
        with self._lock:
            self._conn.execute(
                "INSERT INTO tracking_events"
                " (token, kind, ip, user_agent, referer, enrichment, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (token, kind, ip, user_agent, referer,
                 json.dumps(enrichment or {}), time.time()))
            self._conn.commit()

    def events(self, token: str) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tracking_events WHERE token=? ORDER BY created_at ASC",
                (token,)).fetchall()
        return [dict(r) for r in rows]

    def hits(self) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT e.*, t.email_id, t.campaign_id"
                " FROM tracking_events e JOIN tracking_tokens t ON t.token=e.token"
                " ORDER BY e.created_at DESC LIMIT 500").fetchall()
        return [dict(r) for r in rows]


# ─── Enrichment ──────────────────────────────────────────────────────────────

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def rdap_lookup(ip: str, timeout: float = 5.0) -> dict:
    """RDAP registry lookup via rdap.org (follows registry redirect)."""
    try:
        req = urllib.request.Request(
            f"https://rdap.org/ip/{ip}", headers={"User-Agent": "phishing-detector/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        net = data.get("network", {})
        entities = data.get("entities", [])
        org = ""
        for ent in entities:
            vcard = ent.get("vcardArray", [[]])[1]
            for item in vcard:
                if item and item[0] == "fn":
                    org = item[3] if len(item) > 3 else ""
                    break
            if org:
                break
        return {
            "handle": data.get("handle"),
            "ip_version": data.get("ipVersion"),
            "name": net.get("name"),
            "cidr": net.get("startAddress") and (
                f"{net.get('startAddress')}-{net.get('endAddress')}"),
            "start_address": net.get("startAddress"),
            "end_address": net.get("endAddress"),
            "organization": org,
            "port43": net.get("port43"),
            "status": data.get("status", []),
        }
    except Exception as exc:
        return {"error": str(exc)[:160]}


def enrich_request(ip: str, timeout: float = 5.0) -> dict:
    """Geo-IP + RDAP registry + reverse DNS for a freshly observed IP."""
    if not ip:
        return {"error": "no ip"}
    enriched = {"ip": ip, "reverse": reverse_dns(ip)}
    try:
        from services.geoip_service import GeoIPService
        geo = GeoIPService().lookup_ip(ip)
        enriched["geo"] = geo if geo.get("ok") else None
    except Exception:
        enriched["geo"] = None
    enriched["rdap"] = rdap_lookup(ip, timeout)
    return enriched


# ─── Public helpers ──────────────────────────────────────────────────────────

def base_url() -> str:
    return os.getenv("TRACKING_BASE_URL", "http://localhost:8081").rstrip("/")


def mint_email_token(email_id: str = "", campaign_id: str = "",
                     store: TrackerStore = None) -> str:
    store = store or TrackerStore()
    return store.mint(email_id, campaign_id)


def open_url(token: str) -> str:
    """Pixel URL to embed in an outbound email body."""
    return f"{base_url()}/track/{token}/pixel.gif"


def redirect_url(token: str, target: str) -> str:
    """Click-redirect URL that logs the click then bounces to `target`."""
    return f"{base_url()}/redir/{token}?u={urllib.parse.quote(target, safe='')}"


def embed_html(token: str, target: str = "") -> str:
    """Ready-to-paste <img> (and optional anchor) snippet for an email body."""
    parts = [f'<img src="{open_url(token)}" width="1" height="1" alt="" />']
    if target:
        parts.append(f'<a href="{redirect_url(token, target)}">{target}</a>')
    return "\n".join(parts)