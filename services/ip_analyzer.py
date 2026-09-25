"""
services/ip_analyzer.py - Explainable risk analysis for extracted IP intelligence.

Pipeline:
    extraction (services/ip_extractor)
        -> classify every IP (utils/ip_utils)
        -> geolocate public IPs (services/geoip_service)
        -> per-IP risk score + forensic explanation
        -> header correlation rows  (email -> header -> IP -> geo/ISP/ASN/risk)
        -> module-level summary

Design notes on the explanations:
  * Geographic context is described as "Probable geographic/network context" -
    NEVER as the attacker's exact physical location.
  * IP reputation alone is NEVER the basis for classifying an email as
    phishing; wording stresses that this is supporting evidence only.
"""

from geo_engine import HIGH_RISK_COUNTRIES  # reuse existing country risk table
from utils.ip_utils import ip_type_label
from services.geoip_service import GeoIPService

# Additional network-related signals that indicate hosting/datacenter space.
_HOSTING_ORG_MARKERS = [
    "hosting", "datacenter", "data center", "cloud", "digitalocean",
    "amazon aws", "amazon.com", "google cloud", "google llc", "microsoft azure",
    "contabo", "hetzner", "ovh", "rackspace", "linode", "vultr", "leaseweb",
    "gcore", "timeweb", "namecheap hosting",
]
_ASN_HOSTING_MARKERS = ["as-", "host", "datacenter", "cloud", "colo"]


def _risk_score_from_geo(geo: dict) -> float:
    """Convert a GeoIP risk_level ('high'/'moderate'/'low'/'clean') to points."""
    if not geo or not geo.get("ok"):
        return 0.0
    level = (geo.get("risk_level") or "unknown").lower()
    if level == "high":
        return 45.0
    if level == "moderate":
        return 30.0
    if level == "low":
        return 15.0
    if level == "clean":
        return 0.0
    return 0.0


def _looks_like_hosting(geo: dict) -> bool:
    """Heuristic: is the ASN/org of a hosting/datacenter provider?"""
    if not geo or not geo.get("ok"):
        return False
    if geo.get("hosting") is True:
        return True
    org = str(geo.get("organization") or "").lower()
    asn = str(geo.get("asn") or "").lower()
    return any(m in org for m in _HOSTING_ORG_MARKERS) or \
        any(m in asn for m in _ASN_HOSTING_MARKERS)


def assess_ip_risk(ip, classification, geo=None, occurrences=1, context=None) -> dict:
    """
    Simple, explainable per-IP risk assessment.

    context (optional) may contain:
        {"sender_country": str}  - e.g. from domain/WHOIS intelligence, used to
                                   flag geographic inconsistency.
    """
    indicators = []
    score = 0.0

    if not classification.get("is_public"):
        return {
            "ip": ip,
            "risk_level": "low",
            "score": 0,
            "indicators": [
                f"IP is {ip_type_label(classification.get('type', 'invalid'))} "
                "and is not queried against external threat intelligence."
            ],
            "geo": geo,
            "explanation": build_forensic_explanation(ip, classification, geo, indicators),
        }

    indicators.append("Public IP observed in email headers")

    if geo is not None and geo.get("ok"):
        country = (geo.get("country") or "").strip()
        if country in HIGH_RISK_COUNTRIES:
            score += 20
            indicators.append(
                f"Probable geographic/network context: {country} "
                f"(region associated with elevated threat-actor volume)")

        if _looks_like_hosting(geo):
            score += 25
            indicators.append("IP associated with a hosting/datacenter provider")

        if (geo.get("reputation") or {}).get("score") is not None and \
                (geo.get("risk_level") or "").lower() in ("high", "moderate"):
            score += _risk_score_from_geo(geo)
            indicators.append(
                f"Provider reputation reports the IP as "
                f"{geo.get('risk_level', 'unknown').upper()} risk")

        if geo.get("hosting") is True and geo.get("risk_level") == "high":
            score += 10

        if context and context.get("sender_country") and country and \
                context["sender_country"].lower() != country.lower():
            score += 10
            indicators.append(
                f"Geographic/network context ({country}) does not match "
                f"sender-domain intelligence ({context['sender_country']})")
    else:
        code = "Geolocation unavailable" if geo is not None else "No geolocation data"
        indicators.append(f"{code} - risk based on header/IP evidence only")

    if occurrences and occurrences > 1:
        score += 10
        indicators.append(f"IP documented in {occurrences} source header(s)")

    score = round(min(score, 100.0), 1)

    if score >= 55:
        risk_level = "high"
    elif score >= 30:
        risk_level = "moderate"
    elif score > 0:
        risk_level = "low"
    else:
        risk_level = "clean"

    explanation = build_forensic_explanation(ip, classification, geo, indicators)
    return {
        "ip": ip,
        "risk_level": risk_level,
        "score": score,
        "indicators": indicators,
        "geo": geo,
        "explanation": explanation,
    }


def build_forensic_explanation(ip, classification, geo, indicators) -> str:
    """
    Short, human-readable forensic explanation for an IP.
    Geographic context is framed as *probable network context*, not location.
    """
    sources = ""
    if classification.get("sources"):
        names = sorted({s["header"] for s in classification["sources"]})
        sources = " and ".join(names)

    if not classification.get("is_public"):
        if not sources:
            channel = "the Received header"
        elif " and " in sources:
            channel = "the " + sources + " headers"
        else:
            channel = "the " + sources + " header"
        base = (
            f"{ip_type_label(classification.get('type', 'address'))} address "
            f"observed in {channel}. "
            "This is not routed public infrastructure and provides no remote "
            "attribution; it reflects test/internal/relay addressing.")
        return base

    parts = []
    geo_bits = []
    if sources:
        if " and " in sources:
            channel = "the " + sources + " headers"
        else:
            channel = "the " + sources + " header"
        geo_bits.append(f"observed in {channel}")
    else:
        geo_bits.append("observed in email headers")
    prefix = f"Public IP {ip} " + "".join(geo_bits) + "."

    if geo and geo.get("ok"):
        loc = []
        if geo.get("city"):
            loc.append(geo["city"])
        if geo.get("region"):
            loc.append(geo["region"])
        if geo.get("country"):
            loc.append(geo["country"])
        if loc:
            parts.append("Probable geographic/network context: " + ", ".join(loc) + ".")
        net = []
        if geo.get("isp"):
            net.append(f"ISP {geo['isp']}")
        if geo.get("asn"):
            net.append(f"ASN {geo['asn']}")
        if net:
            parts.append("Network " + "; ".join(net) + ".")
    else:
        parts.append("Geolocation unavailable.")

    for indicator in indicators:
        low = indicator.lower()
        if "hosting" in low or "datacenter" in low:
            parts.append("The IP is associated with a hosting provider.")
        elif "reputation" in low or "risk" in low:
            parts.append("The IP has a suspicious reputation.")
        elif "high-risk" in low or "threat-actor" in low:
            parts.append("The IP sits in a network region with elevated threat-actor volume.")
        elif "does not match" in low:
            parts.append("Network/geographic context is inconsistent with other evidence.")

    parts.append(
        "This is supporting evidence and should be correlated with header "
        "authentication, domain intelligence and email content.")
    return prefix + " " + " ".join(parts)


def _occurrences_map(extraction) -> dict:
    """Count how many source headers document the same IP."""
    counts = {}
    for rec in extraction.get("ips", []):
        counts[rec["ip"]] = len(rec.get("sources", []))
    return counts


def run_ip_intelligence(extraction, geoip_service=None, context=None, threat_intel_service=None) -> dict:
    """
    Full IP intelligence pipeline for an extraction dict.

    geoip_service:        GeoIPService instance (default: configured service).
    context:              optional dict (see assess_ip_risk).
    threat_intel_service: ThreatIntelService instance (default: configured service).
    """
    geoip_service = geoip_service or GeoIPService()
    from services.geoip_service import get_geoip_config
    config = get_geoip_config()

    email_id = extraction.get("email_id", "unknown")
    occurrences = _occurrences_map(extraction)

    ip_results = []
    for record in extraction.get("ips", []):
        ip = record["ip"]
        classification = {
            "ip": record["ip"],
            "is_public": record["is_public"],
            "type": record["type"],
            "subtype": record["subtype"],
            "version": record["version"],
            "valid": True,
            "sources": record.get("sources", []),
        }
        geo = None
        if record["is_public"]:
            geo = geoip_service.lookup_ip(ip)
        assessment = assess_ip_risk(
            ip, classification, geo=geo,
            occurrences=occurrences.get(ip, 1), context=context)
        ip_results.append({
            "ip": ip,
            "version": record["version"],
            "type": record["type"],
            "type_label": ip_type_label(record["type"]),
            "subtype": record.get("subtype"),
            "is_public": record["is_public"],
            "sources": record.get("sources", []),
            "geo": geo,
            "risk_level": assessment["risk_level"],
            "score": assessment["score"],
            "indicators": assessment["indicators"],
            "explanation": assessment["explanation"],
        })

    # Enrich public IPs with AbuseIPDB threat intelligence
    try:
        from services.threat_intel import enrich_ip_results, ThreatIntelService
        threat_intel_service = threat_intel_service or ThreatIntelService()
        ip_results = enrich_ip_results(
            ip_results, threat_intel_service=threat_intel_service, context=context)
    except Exception:
        pass

    # Header correlation rows:  email -> header -> IP -> geo/ISP/ASN/risk.
    correlations = []
    for result in ip_results:
        geo = result["geo"] or {}
        for source in result["sources"]:
            correlations.append({
                "email_id": email_id,
                "header": source["header"],
                "hop": source.get("hop"),
                "ip": result["ip"],
                "type": result["type_label"],
                "country": geo.get("country"),
                "region": geo.get("region"),
                "city": geo.get("city"),
                "isp": geo.get("isp"),
                "asn": geo.get("asn"),
                "risk_level": result["risk_level"],
            })

    public_ips = [r for r in ip_results if r["is_public"]]
    suspicious = [r for r in ip_results if r["risk_level"] in ("high", "moderate")]
    max_score = max((r["score"] for r in ip_results), default=0)

    if max_score >= 55:
        summary_level = "high"
    elif max_score >= 30:
        summary_level = "moderate"
    else:
        summary_level = "low"

    return {
        "email_id": email_id,
        "geoip_config": config,
        "summary": {
            "total_ips": len(ip_results),
            "public_ips": len(public_ips),
            "private_reserved_ips": len(ip_results) - len(public_ips),
            "suspicious_ips": len(suspicious),
            "risk_level": summary_level,
            "max_score": max_score,
        },
        "ip_results": ip_results,
        "correlations": correlations,
        "explanations": [r["explanation"] for r in suspicious],
    }