"""
utils/ip_utils.py - IP address validation and classification helpers.

Uses Python's stdlib `ipaddress` module. Provides a deterministic,
explainable classifier that distinguishes:

    public | private | loopback | reserved | multicast |
    documentation | link_local | shared | unspecified

Documentation/test ranges (RFC 5737, RFC 3849) and similar non-routable
space are never treated as "public" so that they are NOT sent to an
external GeoIP API.
"""

import ipaddress
import re

# ─── Regex patterns (candidate extraction is done by services/ip_extractor.py) ──

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPv6 candidate pattern for header text. Deliberately over-matches (any
# hex/digit-dot/colon run containing a colon); every candidate is later
# validated with ipaddress.ip_address(), which is the authoritative check.
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])(?=[0-9A-Fa-f]*:)[0-9A-Fa-f:.]+(?<![.])"
)

# ─── Classification networks (explicit, deterministic) ────────────────────────

_RFC1918_IPV4 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

_DOCUMENTATION_IPV4 = [
    ipaddress.IPv4Network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),    # TEST-NET-3
]
_DOCUMENTATION_IPV6 = ipaddress.IPv6Network("2001:db8::/32")

_BENCHMARK_IPV4 = ipaddress.IPv4Network("198.18.0.0/15")
_SHARED_IPV4 = ipaddress.IPv4Network("100.64.0.0/10")      # CGNAT
_IPV6_ULA = ipaddress.IPv6Network("fc00::/7")              # unique local
_IPV6_LINK_LOCAL = ipaddress.IPv6Network("fe80::/10")
_IPV6_TEREDO = ipaddress.IPv6Network("2001::/32")
_IPV6_6TO4 = ipaddress.IPv6Network("2002::/16")
_IPV6_SITE_LOCAL = ipaddress.IPv6Network("fec0::/10")      # deprecated

_ARTIFACT_CHARS = " \t\r\n[]()<>\",;`'"


def strip_ip_artifacts(value: str) -> str:
    """Remove brackets, quotes, whitespace and other header decoration."""
    if value is None:
        return ""
    s = str(value).strip()
    s = s.strip(_ARTIFACT_CHARS)
    if s.lower().startswith("ipv6:"):
        s = s[5:]
        s = s.strip(_ARTIFACT_CHARS)
    return s.strip()


def parse_ip(value: str):
    """Return a normalized ipaddress object, or None if invalid."""
    cleaned = strip_ip_artifacts(value)
    if not cleaned:
        return None
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        return None


def is_valid_ip(value: str) -> bool:
    """True if the value parses as a valid IPv4 or IPv6 address."""
    return parse_ip(value) is not None


def _contains(networks, ip) -> bool:
    return any(ip in net for net in networks)


def classify_ip(value: str) -> dict:
    """
    Classify an IP address.

    Returns:
        {
          "ip": <canonical string form>,
          "valid": bool,
          "version": 4 | 6 | None,
          "type": "public"|"private"|"loopback"|"reserved"|"multicast"
                  |"documentation"|"link_local"|"shared"|"unspecified"|"invalid",
          "subtype": optional string,
          "is_public": bool  (True only when safe to send to a GeoIP API)
        }
    """
    ip = parse_ip(value)
    if ip is None:
        return {
            "ip": strip_ip_artifacts(value),
            "valid": False,
            "version": None,
            "type": "invalid",
            "subtype": None,
            "is_public": False,
        }

    # Unwrap IPv4-mapped IPv6 addresses to their embedded IPv4.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    normalized = str(ip)
    version = ip.version

    ip_type = "public"
    subtype = None

    if ip.is_unspecified:
        ip_type = "unspecified"
    elif ip.is_loopback:
        ip_type = "loopback"
    elif ip.is_multicast:
        ip_type = "multicast"

    elif _contains(_DOCUMENTATION_IPV4, ip) or (
        isinstance(ip, ipaddress.IPv6Address) and ip in _DOCUMENTATION_IPV6
    ):
        ip_type = "documentation"
        subtype = "test/documentation range"

    elif version == 4:
        if _contains(_RFC1918_IPV4, ip):
            ip_type = "private"
        elif ip in _SHARED_IPV4:
            ip_type = "shared"
            subtype = "CGNAT (100.64/10)"
        elif ip in _BENCHMARK_IPV4:
            ip_type = "reserved"
            subtype = "benchmark (198.18/15)"
        elif ip.is_link_local:
            ip_type = "link_local"
        elif ip.is_reserved:
            ip_type = "reserved"
        else:
            ip_type = "public"

    else:  # IPv6
        if ip in _IPV6_ULA:
            ip_type = "private"
        elif ip in _IPV6_LINK_LOCAL:
            ip_type = "link_local"
        elif ip in _IPV6_TEREDO:
            ip_type = "reserved"
            subtype = "Teredo tunnel (2001::/32)"
        elif ip in _IPV6_6TO4:
            ip_type = "reserved"
            subtype = "6to4 (2002::/16)"
        elif ip in _IPV6_SITE_LOCAL:
            ip_type = "reserved"
            subtype = "deprecated site-local (fec0::/10)"
        elif ip.is_reserved or ip.is_site_local:
            ip_type = "reserved"
        else:
            ip_type = "public"

    return {
        "ip": normalized,
        "valid": True,
        "version": version,
        "type": ip_type,
        "subtype": subtype,
        "is_public": ip_type == "public",
    }


def ip_type_label(ip_type: str) -> str:
    """Human friendly display label for an IP classification type."""
    return {
        "public": "Public",
        "private": "Private",
        "loopback": "Loopback",
        "reserved": "Reserved",
        "multicast": "Multicast",
        "documentation": "Documentation/Test",
        "link_local": "Link-Local",
        "shared": "Shared (CGNAT)",
        "unspecified": "Unspecified",
        "invalid": "Invalid",
    }.get(ip_type, ip_type.capitalize())