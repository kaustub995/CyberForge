"""
services/geoip_service.py - Configurable GeoIP / IP-intelligence service layer.

The API provider is NOT hard-coded. It is configured via environment variables:

    GEOIP_API_URL    (e.g. "https://ipapi.co/{ip}/json" or "https://api.example.com/ip")
    GEOIP_API_KEY
    GEOIP_TIMEOUT    (seconds, default 10)

The `{ip}` placeholder in GEOIP_API_URL is replaced with the target address.
Without a placeholder, the IP is appended as a query parameter (`?ip=...`).

The service is provider-agnostic: response body keys are normalized from the
common field naming conventions used by ip-api.com, ipapi.co, ipinfo.io,
IPQualityScore, AbuseIPDB, ipdata.co, ipregistry, etc. Only fields the
provider actually returns are populated.

The service never raises on network/API errors; every failure is returned as a
structured dict so callers can display "Geolocation unavailable" instead of
crashing.
"""

import os
import time

try:
    import requests
    HAS_REQUESTS = True
except ImportError:  # pragma: no cover - defensive
    HAS_REQUESTS = False

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover - dotenv is optional
    pass


# ─── Canonical schema ─────────────────────────────────────────────────────────
# mapping: canonical_field -> list of plausible provider response keys
_FIELD_ALIASES = {
    "ip": ["ip", "query", "ip_address", "IP"],
    "country": ["country", "country_name", "countryName", "country_name"],
    "country_code": ["country_code", "countryCode", "country_iso", "countrycode"],
    "region": ["region", "regionName", "region_name", "state", "state_prov", "division", "province"],
    "city": ["city", "locality", "city_name"],
    "latitude": ["latitude", "lat"],
    "longitude": ["longitude", "lon", "lng", "long"],
    "isp": ["isp", "ISP", "connection_isp"],
    "organization": ["org", "organization", "org_name", "isp_org", "carrier"],
    "asn": ["as", "asn", "as_info", "autonomous_system_number", "autonomous_system_asn"],
    "timezone": ["timezone", "time_zone", "utc_offset"],
}

# Boolean / numeric signals for hosting, proxy and VPN-like infrastructure.
_HOSTING_KEYS = ["hosting", "is_datacenter", "datacenter"]
_PROXY_KEYS = ["proxy", "is_proxy", "tor", "is_tor", "vpn", "is_vpn", "anonymous"]

# Reputation / threat-intelligence scores across providers.
_REPUTATION_SCORE_KEYS = [
    "fraud_score",            # IPQualityScore
    "abuseConfidenceScore",   # AbuseIPDB
    "threat_score",           # ipapi.co / generic
    "risk_score",             # ipregistry
    "risk",                   # ipinfo/ipapi variants
    "reputation_score",
]
_REPUTATION_LABEL_KEYS = [
    "reputation",           # plain text label (clean/suspicious/malicious)
    "risk_level",
    "threat_level",
    "verdict",
    "classification",
    "type",
]

_RISK_THRESHOLDS = [
    (80, "high"),
    (50, "moderate"),
    (30, "low"),
]


def _first(data: dict, keys):
    for k in keys:
        val = data.get(k)
        if val is not None and str(val) != "" and str(val).lower() != "null":
            return val
    return None


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _reputation_markers(data: dict) -> list:
    """Collect plain-language reputation markers (e.g. 'malicious')."""
    markers = []
    for key in _REPUTATION_LABEL_KEYS:
        val = data.get(key)
        if isinstance(val, bool):
            continue
        if isinstance(val, (list, dict)):
            continue
        if isinstance(val, str) and val.strip():
            markers.append(val.strip())
    return markers


def get_geoip_config() -> dict:
    """
    Read GeoIP configuration from the environment.

    Returns:
        {
          "enabled": bool,
          "url": str,
          "has_key": bool,
          "timeout": float,
          "message": str   (user facing configuration hint)
        }
    """
    url = (os.getenv("GEOIP_API_URL") or "").strip()
    key = (os.getenv("GEOIP_API_KEY") or "").strip()
    try:
        timeout = float(os.getenv("GEOIP_TIMEOUT") or "10")
    except ValueError:
        timeout = 10.0
    timeout = max(1.0, min(timeout, 60.0))

    enabled = bool(url)
    if enabled:
        message = (
            "GeoIP provider configured."
            if key
            else "GeoIP provider configured without an API key."
        )
    else:
        message = (
            "GeoIP API not configured. Set GEOIP_API_URL (and GEOIP_API_KEY) "
            "in your environment or .env file to enable geolocation. "
            "IP validation and risk analysis continue without geolocation data."
        )

    return {
        "enabled": enabled,
        "url": url,
        "has_key": bool(key),
        "timeout": timeout,
        "message": message,
    }


class GeoIPService:
    """
    Configurable GeoIP/intelligence lookup service with structured output,
    error categorization and a small in-memory cache for duplicate IPs.
    """

    def __init__(self, url=None, api_key=None, timeout=None, http_get=None):
        self.url = (url if url is not None else (os.getenv("GEOIP_API_URL") or "")).strip()
        self.api_key = api_key if api_key is not None else (os.getenv("GEOIP_API_KEY") or "").strip()
        if timeout is None:
            try:
                timeout = float(os.getenv("GEOIP_TIMEOUT") or "10")
            except ValueError:
                timeout = 10.0
        self.timeout = max(1.0, min(float(timeout), 60.0))
        self.enabled = bool(self.url)
        self._http_get = http_get or (requests.get if HAS_REQUESTS else None)
        self._cache = {}

    # ── Public API ───────────────────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> dict:
        """Return canonical, enriched location/intelligence data for an IP.

        Never raises. On failure returns {"ok": False, "category", "error"}.
        Private/reserved/documentation IPs are rejected by the caller
        (ip_analyzer) before they reach this service.
        """
        ip = ip.strip().strip("[]")
        cached = self._cache.get(ip)
        if cached is not None:
            return dict(cached)

        if not self.enabled:
            result = self._failure(ip, "not_configured",
                                   "GeoIP API not configured (GEOIP_API_URL not set).")
            self._cache[ip] = result
            return result

        if self._http_get is None:
            result = self._failure(ip, "unavailable", "requests library not installed.")
            self._cache[ip] = result
            return result

        url, params, headers = self._build_request(ip)
        started = time.time()
        try:
            response = self._http_get(url, params=params, headers=headers, timeout=self.timeout)
        except Exception as exc:  # requests.RequestException, socket errors, etc.
            category = self._error_category(exc)
            result = self._failure(ip, category, f"{category}: {exc}")
            self._cache[ip] = result
            return result

        elapsed = time.time() - started
        if response.status_code == 401 or response.status_code == 403:
            result = self._failure(
                ip, "invalid_key",
                f"GeoIP API returned HTTP {response.status_code} - invalid/missing API key.")
        elif response.status_code == 429:
            result = self._failure(ip, "rate_limit",
                                   "GeoIP API rate limit reached (HTTP 429).")
        elif response.status_code >= 500:
            result = self._failure(ip, "unavailable",
                                   f"GeoIP API unavailable (HTTP {response.status_code}).")
        elif response.status_code != 200:
            result = self._failure(
                ip, "http_error",
                f"GeoIP API returned HTTP {response.status_code}.")
        else:
            try:
                raw = response.json()
            except Exception:
                raw = None
            if not isinstance(raw, dict):
                result = self._failure(ip, "invalid_json",
                                       "GeoIP API returned an unrecognized response body.")
            else:
                result = self._build_success(ip, raw, elapsed)

        self._cache[ip] = result
        return result

    # ── Internals ────────────────────────────────────────────────────────────

    def _build_request(self, ip: str):
        headers = {"User-Agent": "CyberForge-IPIntelligence/1.0"}
        params = {}
        url = self.url
        if "{ip}" in url:
            url = url.replace("{ip}", ip)
        else:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}ip={ip}"
        if self.api_key:
            headers["X-Api-Key"] = self.api_key
            params["apikey"] = self.api_key
        return url, params, headers

    @staticmethod
    def _error_category(exc) -> str:
        name = type(exc).__name__
        lower = str(exc).lower()
        if "timeout" in name.lower() or "timed out" in lower:
            return "timeout"
        if name in ("ConnectionError", "ConnectionResetError",
                    "NewConnectionError", "ConnectTimeout"):
            return "unavailable"
        return "api_error"

    @staticmethod
    def _failure(ip, category, error) -> dict:
        return {
            "ok": False,
            "ip": ip,
            "category": category,
            "error": error,
            "country": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "isp": None,
            "organization": None,
            "asn": None,
            "timezone": None,
            "hosting": None,
            "reputation": None,
            "risk_level": None,
        }

    @staticmethod
    def _build_success(ip, raw: dict, elapsed: float) -> dict:
        result = {
            "ok": True,
            "ip": _first(raw, _FIELD_ALIASES["ip"]) or ip,
            "country": _first(raw, _FIELD_ALIASES["country"]),
            "region": _first(raw, _FIELD_ALIASES["region"]),
            "city": _first(raw, _FIELD_ALIASES["city"]),
            "latitude": _to_float(_first(raw, _FIELD_ALIASES["latitude"])),
            "longitude": _to_float(_first(raw, _FIELD_ALIASES["longitude"])),
            "isp": _first(raw, _FIELD_ALIASES["isp"]),
            "organization": _first(raw, _FIELD_ALIASES["organization"]),
            "asn": _first(raw, _FIELD_ALIASES["asn"]),
            "timezone": _first(raw, _FIELD_ALIASES["timezone"]),
            "hosting": None,
            "reputation": None,
            "risk_level": None,
        }

        any_flag = None
        for key in _HOSTING_KEYS + _PROXY_KEYS:
            val = raw.get(key)
            if isinstance(val, bool):
                any_flag = any_flag or val
            elif isinstance(val, (int, float)):
                any_flag = any_flag or bool(val)
            elif isinstance(val, str) and val.lower() in ("true", "yes", "1"):
                any_flag = True
        if any_flag is not None:
            result["hosting"] = bool(any_flag)

        result["reputation"] = _extract_reputation(raw)
        result["risk_level"] = _risk_from_reputation(result["reputation"])
        result["response_time_seconds"] = round(elapsed, 3)
        result["raw_fields"] = list(raw.keys()) if isinstance(raw, dict) else []
        return result


def _extract_reputation(raw: dict) -> dict:
    """Extract whatever reputation/intelligence the provider offers."""
    reputation = {"provider_keys": []}

    score = _first(raw, _REPUTATION_SCORE_KEYS)
    score = _to_float(score)
    if isinstance(raw.get("reputation"), (int, float)) and not isinstance(
            raw.get("reputation"), bool):
        score = raw["reputation"]

    if score is not None:
        reputation["score"] = score
        reputation["source"] = "numeric_score"

    markers = _reputation_markers(raw)
    if markers:
        reputation["markers"] = markers
        reputation["source"] = "label"

    malicious_flags = [
        key for key in ("malicious", "is_abuser", "abusive", "threat",
                        "is_attack_surface", "is_fraud", "is_threat") if raw.get(key) is True
    ]
    if malicious_flags:
        reputation["flags"] = malicious_flags
        reputation["source"] = "flag"

    if not reputation.get("score") and not reputation.get("markers") and not reputation.get("flags"):
        return None
    return reputation


def _risk_from_reputation(reputation) -> str:
    """Map provider reputation signals to an explainable risk level."""
    if not reputation:
        return None
    flags = reputation.get("flags") or []
    markers = [m.lower() for m in (reputation.get("markers") or [])]

    if flags or any(word in " ".join(markers) for word in
                    ("malicious", "fraud", "threat", "abusive", "suspicious", "high")):
        if any(word in " ".join(markers) for word in ("malicious", "fraud", "threat")):
            return "high"
        return "moderate"

    score = reputation.get("score")
    if score is not None:
        for threshold, level in _RISK_THRESHOLDS:
            if score >= threshold:
                return level
        return "clean"
    return "unknown"