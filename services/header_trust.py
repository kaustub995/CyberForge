"""
services/header_trust.py - Origin trust model for email header chains.

Adds forensic realism on top of raw IP extraction (services/ip_extractor +
services/ip_analyzer):

  * identifies the EARLIEST RELIABLE public node - the first public IP that is
    NOT a mail-provider and NOT shared hosting/datacenter infrastructure;
  * detects provider-masking - when only mail-provider (Gmail/Outlook/Yahoo/...)
    or datacenter IPs are visible, the UI must never present a datacenter as
    the sender's physical location;

  * forged-header / relay-anomaly heuristics for "fake trails in the header".

Modeled on the practical guidance that a usable origin signal is a public IP
that points outside major provider infrastructure. Everything here is
explainable and framed as "probable network context", never as identity.
"""

import re
from email.utils import parsedate_to_datetime

# ─── Mail providers / bulk-mail infrastructure that mask true sender origin ──
# Matched against geo ISP/org/ASN text. Value is the label shown to analysts.

MAIL_PROVIDER_MARKERS = {
    "google": "Google/Gmail",
    "gmail": "Google/Gmail",
    "outlook": "Microsoft Outlook",
    "microsoft": "Microsoft",
    "o365": "Microsoft 365",
    "yahoo": "Yahoo",
    "aol": "AOL",
    "zoho": "Zoho",
    "protonmail": "ProtonMail",
    "icloud": "Apple iCloud",
    "apple": "Apple",
    "fastmail": "Fastmail",
    "mailgun": "Mailgun",
    "mandrill": "Mandrill",
    "amazonses": "AWS SES",
    "amazon": "AWS",
    "sendgrid": "SendGrid",
    "mailchimp": "Mailchimp",
    "sparkpost": "SparkPost",
}

# Hosting / datacenter markers also handled by ip_analyzer._HOSTING_ORG_MARKERS;
# kept here so origin assessment does not depend on private module constants.
_HOSTING_MARKERS = ("hosting", "datacenter", "data center", "cloud", "colo")


def provider_from_text(text: str):
    """Return the provider label if `text` (ISP/org/ASN) names a provider."""
    if not text:
        return None
    low = str(text).lower()
    for marker, label in MAIL_PROVIDER_MARKERS.items():
        if marker in low:
            return label
    return None


def _namespace_text(geo) -> str:
    if not geo or not geo.get("ok"):
        return ""
    parts = [str(geo.get("isp") or ""), str(geo.get("organization") or ""),
             str(geo.get("asn") or "")]
    return " ".join(parts).lower()


def classify_node(geo, classification) -> dict:
    """
    Classify a single node from the header/IP chain for origin purposes.

    Returns:
        {
          "usable_for_origin": bool,
          "node_class":  "provider" | "hosting" | "public_other" | "non_public" | "unknown",
          "provider":    <provider label or None>,
          "reason":      str
        }
    """
    if not classification or not classification.get("is_public"):
        return {
            "usable_for_origin": False,
            "node_class": "non_public",
            "provider": None,
            "reason": "Not routed public infrastructure - no origin attribution value.",
        }

    text = _namespace_text(geo)
    provider = provider_from_text(text)
    if provider:
        return {
            "usable_for_origin": False,
            "node_class": "provider",
            "provider": provider,
            "reason": f"IP belongs to {provider} infrastructure (origin masked).",
        }

    if geo and geo.get("ok") and (geo.get("hosting") is True or
                                  any(m in text for m in _HOSTING_MARKERS)):
        return {
            "usable_for_origin": False,
            "node_class": "hosting",
            "provider": None,
            "reason": "IP belongs to hosting/datacenter space - probable shared infrastructure.",
        }

    return {
        "usable_for_origin": True,
        "node_class": "public_other",
        "provider": None,
        "reason": "Public IP outside major provider/hosting space - candidate origin.",
    }


def _hop_position(hop):
    """Return an ordering key where smaller = closer to the sender.

    X-Originating-IP / X-Real-IP type headers are sender-side signals and are
    treated as 'before' every Received hop. Within Received headers, the LAST
    line in the message is the FIRST received (originating) hop.
    """
    if hop is None:
        return -2
    # Extraction hop 0 = newest Received line; invert so higher hop = earlier.
    return -(int(hop) + 1)


def assess_origin(extraction, ip_results) -> dict:
    """
    Build an origin-trust assessment from an extraction + ip_intel results.

    Returns:
        {
          "earliest_reliable_ip":  str|None,
          "earliest_reliable_geo": dict|None,
          "provider_masked":       bool,
          "masking_providers":     [labels],
          "node_classes":          {ip: node_class},
          "all_hosting_or_provider": bool,
          "assessment":            "attributed"|"provider_masked"|"hosting_only"|"no_public_ip",
          "summary":               str,
        }
    """
    ips = list(ip_results or [])

    # Prefer earliest-in-chain ordering.
    def _order(rec):
        hops = [s.get("hop") for s in rec.get("sources", []) if s.get("header") == "Received"]
        best = min((_hop_position(h) for h in hops), default=0)
        if rec.get("sources") and any(s["header"].startswith("X-") for s in rec["sources"]):
            best = -1
        return best

    ips.sort(key=_order)

    classes = {}
    masking_providers = []
    for rec in ips:
        node = classify_node(rec.get("geo"), {"is_public": rec.get("is_public")})
        classes[rec["ip"]] = node["node_class"]
        if node["node_class"] == "provider" and node["provider"]:
            masking_providers.append(node["provider"])
    masking_providers = list(dict.fromkeys(masking_providers))

    public = [r for r in ips if r.get("is_public")]
    if not public:
        return {
            "earliest_reliable_ip": None,
            "earliest_reliable_geo": None,
            "provider_masked": False,
            "masking_providers": [],
            "node_classes": classes,
            "all_hosting_or_provider": False,
            "assessment": "no_public_ip",
            "summary": "No routable public IP present in headers - origin cannot be attributed.",
        }

    earliest = min(public, key=_order)  # closest to the sender across the chain
    node = classify_node(earliest.get("geo"), {"is_public": True})

    if node["usable_for_origin"]:
        return {
            "earliest_reliable_ip": earliest["ip"],
            "earliest_reliable_geo": earliest.get("geo"),
            "provider_masked": False,
            "masking_providers": [],
            "node_classes": classes,
            "all_hosting_or_provider": False,
            "assessment": "attributed",
            "summary": (
                f"Earliest reliable public node {earliest['ip']} sits outside "
                "provider/hosting space - candidate origin signal."),
        }

    any_hosting = any(c == "hosting" for c in classes.values())
    any_provider = any(c == "provider" for c in classes.values())

    if any_provider:
        return {
            "earliest_reliable_ip": None,
            "earliest_reliable_geo": None,
            "provider_masked": True,
            "masking_providers": masking_providers,
            "node_classes": classes,
            "all_hosting_or_provider": not any_hosting and any_provider,
            "assessment": "provider_masked",
            "summary": (
                f"Origin masked - headers only expose provider infrastructure"
                f" ({', '.join(masking_providers) or 'mail provider'}). This is NOT "
                "the sender's location."),
        }

    return {
        "earliest_reliable_ip": None,
        "earliest_reliable_geo": None,
        "provider_masked": False,
        "masking_providers": [],
        "node_classes": classes,
        "all_hosting_or_provider": any_hosting,
        "assessment": "hosting_only",
        "summary": (
            "Only hosting/datacenter infrastructure visible - probable shared or "
            "anonymized (VPN/proxy/cloud) origin. Unreliable as a sender location."),
    }


# ─── Forged-header / relay-anomaly heuristics ────────────────────────────────

_DATE_RE = re.compile(r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s*\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}")


def _parse_date(value):
    if not value:
        return None
    match = _DATE_RE.search(value)
    if not match:
        return None
    try:
        dt = parsedate_to_datetime(match.group(0))
        return dt.replace(tzinfo=None)
    except Exception:
        return None


def detect_header_anomalies(extraction) -> list:
    """
    Heuristic checks for forged relay chains. Returns a list of findings
    (strings with emoji prefix, matching existing UI conventions).

    Checks:
      * Received lines written in non-chronological order (forged trails);
      * near-duplicate Received lines (copy-paste forging);
      * Received timestamps inconsistent with the Date header.
    """
    findings = []

    # Extract one raw Received line per hop, newest (hop 0) first.
    seen = {}
    for rec in extraction.get("ips", []):
        for src in rec.get("sources", []):
            if src.get("header") == "Received":
                seen.setdefault(src.get("hop"), src.get("raw", ""))
    lines = [seen[h] for h in sorted(seen)]
    if len(lines) < 2:
        return findings

    # Dedupe check (copy-paste forging).
    seen_raw = set()
    for raw in lines:
        if raw in seen_raw:
            findings.append("🟠 Duplicate Received line values - possible fabricated relay trail")
            break
        seen_raw.add(raw)

    # Chronology: newest Received (line 0) should sort AFTER older Received lines.
    dates = [_parse_date(raw) for raw in lines]
    if all(dates):
        reversed_dates = list(reversed(dates))  # oldest -> newest
        if reversed_dates != sorted(reversed_dates):
            findings.append(
                "🟠 Received header timestamps are not chronological - "
                "possible forged relay trail (fake hops).")

    return findings