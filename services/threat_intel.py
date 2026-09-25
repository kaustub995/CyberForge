"""
services/threat_intel.py - External threat-intelligence layer (AbuseIPDB).

Provider-agnostic, mirroring services/geoip_service.py:

    ABUSEIPDB_API_URL   (default: https://api.abuseipdb.com/api/v2/check)
    ABUSEIPDB_API_KEY
    THREAT_INTEL_TIMEOUT (seconds, default 10)

Enriches public IPs with AbuseIPDB signals and produces an explainable
infrastructure classification:

    datacenter | vps | tor | proxy | mail | hosting | unknown

The service never raises on network/API errors; every failure is returned as a
structured {"ok": False, "category", "error"} dict so callers degrade gracefully
when the API key is unavailable.
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

DEFAULT_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# AbuseIPDB usageType -> infrastructure family. Public API values as of v2.
_USAGE_TYPE_MAP = {
    "data center hosting": "datacenter",
    "web hosting": "hosting",
    "vps hosting": "vps",
    "tor node": "tor",
    "open proxy": "proxy",
    "proxy": "proxy",
    "vpn": "proxy",
    "email hosting": "mail",
    "mail server": "mail",
    "search engine bot": "bot",
    "spider": "bot",
    "content delivery network": "cdn",
    "university": "education",
    "government": "government",
    "commercial": "commercial",
    "residential": "residential",
    "unknown": "unknown",
}


def get_threat_intel_config() -> dict:
    """Read threat-intel configuration from environment."""
    url = (os.getenv("ABUSEIPDB_API_URL") or "").strip() or DEFAULT_ABUSEIPDB_URL
    key = (os.getenv("ABUSEIPDB_API_KEY") or "").strip()
    try:
        timeout = float(os.getenv("THREAT_INTEL_TIMEOUT") or "10")
    except ValueError:
        timeout = 10.0
    timeout = max(1.0, min(timeout, 60.0))

    enabled = bool(key)
    if enabled:
        message = "AbuseIPDB threat-intelligence provider configured."
    else:
        message = (
            "AbuseIPDB not configured. Set ABUSEIPDB_API_KEY in your environment "
            "or .env file to enable threat-intelligence enrichment. "
            "IP validation and risk analysis continue without it."
        )

    return {
        "enabled": enabled,
        "url": url,
        "has_key": bool(key),
        "timeout": timeout,
        "message": message,
    }


def infrastructure_type(usage_type) -> str:
    """Map an AbuseIPDB usageType string to a stable infrastructure family."""
    if not usage_type:
        return "unknown"
    low = str(usage_type).strip().lower()
    for key, family in _USAGE_TYPE_MAP.items():
        if key in low:
            return family
    return "unknown"


class ThreatIntelService:
    """AbuseIPDB-backed threat-intelligence lookup with structured output."""

    def __init__(self, api_key=None, url=None, timeout=None, http_get=None):
        self.api_key = (api_key if api_key is not None
                        else (os.getenv("ABUSEIPDB_API_KEY") or "").strip())
        self.url = ((url if url is not None else (os.getenv("ABUSEIPDB_API_URL") or "").strip())
                    or DEFAULT_ABUSEIPDB_URL)
        if timeout is None:
            try:
                timeout = float(os.getenv("THREAT_INTEL_TIMEOUT") or "10")
            except ValueError:
                timeout = 10.0
        self.timeout = max(1.0, min(float(timeout), 60.0))
        self.enabled = bool(self.api_key)
        self._http_get = http_get or (requests.get if HAS_REQUESTS else None)
        self._cache = {}

    def lookup_ip(self, ip: str) -> dict:
        """Check an IP against AbuseIPDB. Never raises."""
        ip = ip.strip().strip("[]")
        cached = self._cache.get(ip)
        if cached is not None:
            return dict(cached)

        if not self.enabled:
            result = self._failure(
                ip, "not_configured",
                "AbuseIPDB not configured (ABUSEIPDB_API_KEY not set).")
            self._cache[ip] = result
            return result

        if self._http_get is None:
            result = self._failure(ip, "unavailable", "requests library not installed.")
            self._cache[ip] = result
            return result

        params = {
            "ipAddress": ip,
            "maxAgeInDays": os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"),
            "verbose": "true",
        }
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "CyberForge-ThreatIntel/1.0",
        }
        started = time.time()
        try:
            response = self._http_get(self.url, params=params, headers=headers,
                                      timeout=self.timeout)
        except Exception as exc:
            result = self._failure(ip, "api_error", f"{type(exc).__name__}: {exc}")
            self._cache[ip] = result
            return result

        if response.status_code == 401 or response.status_code == 403:
            result = self._failure(ip, "invalid_key",
                                   f"AbuseIPDB returned HTTP {response.status_code} - invalid key.")
        elif response.status_code == 429:
            result = self._failure(ip, "rate_limit", "AbuseIPDB rate limit reached (HTTP 429).")
        elif response.status_code >= 500:
            result = self._failure(ip, "unavailable",
                                   f"AbuseIPDB unavailable (HTTP {response.status_code}).")
        elif response.status_code != 200:
            result = self._failure(ip, "http_error",
                                   f"AbuseIPDB returned HTTP {response.status_code}.")
        else:
            try:
                raw = response.json()
            except Exception:
                raw = None
            data = (raw or {}).get("data") if isinstance(raw, dict) else None
            if not isinstance(data, dict):
                result = self._failure(ip, "invalid_json",
                                       "AbuseIPDB returned an unrecognized body.")
            else:
                result = self._build_success(ip, data, time.time() - started)

        self._cache[ip] = result
        return result

    @staticmethod
    def _failure(ip, category, error) -> dict:
        return {
            "ok": False,
            "ip": ip,
            "category": category,
            "error": error,
            "abuse_confidence_score": None,
            "usage_type": None,
            "infrastructure": None,
            "is_tor": None,
            "is_proxy": None,
            "total_reports": None,
            "last_reported_at": None,
            "country_code": None,
            "isp": None,
            "domain": None,
            "risk_level": None,
        }

    def _build_success(self, ip, data: dict, elapsed: float) -> dict:
        usage = data.get("usageType")
        inf = infrastructure_type(usage)
        result = {
            "ok": True,
            "ip": data.get("ipAddress") or ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "usage_type": usage,
            "infrastructure": inf,
            "is_tor": data.get("isTor"),
            "is_proxy": data.get("isProxy"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "risk_level": self._risk_from_signals(data, inf),
            "response_time_seconds": round(elapsed, 3),
        }
        return result

    @staticmethod
    def _risk_from_signals(data: dict, infra: str) -> str:
        score = data.get("abuseConfidenceScore")
        if score is not None:
            if score >= 80:
                return "high"
            if score >= 50:
                return "moderate"
            if score >= 25:
                return "low"
            if score == 0:
                return "clean"
        if infra in ("tor", "proxy", "datacenter", "vps"):
            return "moderate"
        return "unknown"


def enrich_ip_results(ip_results, threat_intel_service=None, context=None):
    """
    Enrich ip_analyzer results with AbuseIPDB intelligence.

    Each public IP record gains a "threat_intel" field. Runs synchronously and
    gracefully skips unconfigured/unreachable lookups. When the AbuseIPDB
    reputation is high, an indicator is appended and the per-IP score is nudged
    (supporting evidence only - never a standalone verdict).
    """
    service = threat_intel_service or ThreatIntelService()
    max_age_days = None

    enriched = []
    total_reports_cap = 3
    for rec in (ip_results or []):
        rec = dict(rec)
        if not rec.get("is_public"):
            rec["threat_intel"] = None
            enriched.append(rec)
            continue
        ti = service.lookup_ip(rec["ip"])
        rec["threat_intel"] = ti
        if ti.get("ok"):
            infra = ti.get("infrastructure")
            indicators = list(rec.get("indicators") or [])
            score = float(rec.get("score") or 0.0)
            if infra in ("tor", "proxy"):
                indicators.append(
                    f"AbuseIPDB: infrastructure classified as {infra.upper()}"
                    " (anonymization/relay space)")
                score += 20
            if infra == "datacenter":
                indicators.append(
                    "AbuseIPDB: IP hosted in datacenter space (origin may be masked)")
                score += 10
            if (ti.get("abuse_confidence_score") or 0) >= 50:
                indicators.append(
                    f"AbuseIPDB reports {ti['abuse_confidence_score']}% abuse confidence"
                    f" ({ti.get('total_reports') or 0} reports) - suspicious reputation")
                score += 15
            if ti.get("is_tor"):
                indicators.append("AbuseIPDB flags IP as a Tor exit node")
                score += 15
            if (ti.get("total_reports") or 0) > total_reports_cap:
                score += 5
            rec["score"] = round(min(score, 100.0), 1)
            rec["risk_level"] = _bump_risk_level(rec.get("risk_level"), rec["score"])
            if indicators and indicators != rec.get("indicators"):
                rec["indicators"] = indicators
                rec["explanation"] = rec.get("explanation", "") + " " + (
                    "AbuseIPDB report is supporting evidence and should be "
                    "correlated with other stages.")
        enriched.append(rec)
    return enriched


def _bump_risk_level(current, score) -> str:
    if score >= 55:
        return "high"
    if score >= 30:
        return "moderate"
    if score > 0:
        return "low"
    return current or "clean"