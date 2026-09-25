"""
services/ip_extractor.py - Extract candidate IP addresses from a parsed email.

Accepts raw email text/bytes (e.g. .eml file contents) or an already-parsed
email.message.Message object. Scans IP-bearing headers, validates every
candidate with the stdlib `ipaddress` module, and de-duplicates IPs while
preserving the headers (and Received-hop position) each IP came from.
"""

import hashlib
from email import policy
from email.parser import BytesParser, Parser

from utils.ip_utils import IPV4_RE, IPV6_RE, parse_ip

# Headers that commonly carry IP addresses (value is a short description).
IP_SOURCE_HEADERS = {
    "Received": "Received routing header",
    "X-Originating-IP": "Originating IP header",
    "X-Sender-IP": "Sender IP header",
    "X-Origin-IP": "Origin IP header",
    "X-Real-IP": "Real routed IP header",
    "X-Forwarded-For": "Forwarded-for chain header",
    "X-Client-IP": "Client IP header",
    "X-Remote-IP": "Remote IP header",
    "X-Remote-Addr": "Remote address header",
    "X-Host": "Original host header",
    "X-Server-IP": "Server IP header",
    "X-Connect": "Connection IP header",
    "X-IP": "Generic IP header",
    "X-Outgoing-Ip": "Outgoing IP header",
}

# Also inspected as generic "other relevant IP headers".
_EXTRA_IP_HEADERS = [
    "X-Announced-Ip", "X-Virus-Scanner-Ip", "X-Abuse-Info",
    "X-Reporting-Abuse", "X-Spam-Source-IP", "X-Open-Relay",
]


import re

_KNOWN_HEADER_NAMES = {
    name.lower(): name for name in list(IP_SOURCE_HEADERS.keys()) + _EXTRA_IP_HEADERS
}


def _candidates_in(value: str):
    """Yield all raw candidate strings that look like an IPv4/IPv6 address."""
    if not value:
        return
    cleaned_value = re.sub(r'(?i)\bipv6:\s*', ' ', str(value))
    for match in IPV4_RE.finditer(cleaned_value):
        yield match.group(0)
    for match in IPV6_RE.finditer(cleaned_value):
        cand = match.group(0)
        if cand.count(":") >= 2 or "::" in cand:
            yield cand


def _extract_raw_headers_from_text(text: str) -> list:
    """
    Extract IP-bearing headers directly from raw text lines.
    Handles folded multiline headers and non-standard line breaks or empty lines before/between headers.
    Returns list of (header_name, header_value).
    """
    if not text:
        return []
    lines = text.splitlines()
    extracted = []
    curr_name = None
    curr_value_lines = []

    for line in lines:
        if line and line[0] in " \t":
            if curr_name:
                curr_value_lines.append(line.strip())
            continue

        matched_name = None
        if ":" in line:
            prefix = line.split(":", 1)[0].strip().lower()
            if prefix in _KNOWN_HEADER_NAMES:
                matched_name = _KNOWN_HEADER_NAMES[prefix]

        if matched_name:
            if curr_name:
                extracted.append((curr_name, " ".join(curr_value_lines)))
            curr_name = matched_name
            curr_value_lines = [line.split(":", 1)[1].strip()]
        else:
            if curr_name:
                extracted.append((curr_name, " ".join(curr_value_lines)))
                curr_name = None
                curr_value_lines = []

    if curr_name:
        extracted.append((curr_name, " ".join(curr_value_lines)))

    return extracted


def parse_email_source(email_source):
    """
    Parse raw email text/bytes into an email.message.Message object.

    Returns (message, error). If `email_source` is already a Message it is
    returned unchanged. Never raises on malformed input.
    """
    if isinstance(email_source, bytes):
        try:
            return BytesParser(policy=policy.default).parsebytes(email_source), None
        except Exception as exc:
            return None, f"Failed to parse email bytes: {exc}"
    if isinstance(email_source, str):
        try:
            return Parser(policy=policy.default).parsestr(email_source), None
        except Exception as exc:
            return None, f"Failed to parse email text: {exc}"
    if hasattr(email_source, "items") and hasattr(email_source, "get_all"):
        return email_source, None
    return None, "Unsupported email source type."


def _email_id_from_message(msg, raw_text="") -> str:
    if msg is not None:
        msg_id = msg.get("Message-ID") if hasattr(msg, "get") else None
        if msg_id:
            return str(msg_id).strip()
    
    # Try finding Message-ID from raw text if msg is None or didn't catch it
    if raw_text:
        for line in raw_text.splitlines():
            if line.lower().startswith("message-id:"):
                val = line.split(":", 1)[1].strip()
                if val:
                    return val

    body = ""
    try:
        if msg is not None and hasattr(msg, "is_multipart") and msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_content() or ""
                    break
        elif msg is not None and hasattr(msg, "get_content"):
            body = msg.get_content() or ""
        else:
            body = raw_text
    except Exception:
        body = raw_text
    return "sha256:" + hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16]


def extract_ips_from_email(email_source, email_id=None) -> dict:
    """
    Extract all candidate IPs from an email.

    Returns:
        {
          "email_id": str,
          "parse_error": str | None,
          "total_ips": int,
          "no_ip": bool,
          "headers_found": [header names that contained IPs],
          "ips": [
             {
               "ip": canonical str,
               "version": 4 | 6,
               "type": classification (from ip_utils.classify_ip),
               "is_public": bool,
               "is_valid": bool,
               "sources": [
                   {"header": "Received", "hop": int|None, "raw": "<header value>"}
               ]
             }, ...
          ]
        }
    """
    msg, parse_error = parse_email_source(email_source)
    raw_text = ""
    if isinstance(email_source, bytes):
        try:
            raw_text = email_source.decode("utf-8", errors="ignore")
        except Exception:
            raw_text = ""
    elif isinstance(email_source, str):
        raw_text = email_source
    elif hasattr(email_source, "as_string"):
        try:
            raw_text = email_source.as_string()
        except Exception:
            raw_text = ""

    if msg is None and not raw_text:
        return {
            "email_id": email_id or "unknown",
            "parse_error": parse_error,
            "total_ips": 0,
            "no_ip": True,
            "headers_found": [],
            "ips": [],
        }

    if not email_id:
        email_id = _email_id_from_message(msg, raw_text=raw_text)

    msg_received = (msg.get_all("Received") or []) if hasattr(msg, "get_all") and msg is not None else []
    received_headers = [str(h) for h in msg_received]

    raw_headers = _extract_raw_headers_from_text(raw_text)

    # Map normalized IP -> record, and which source entries were seen.
    records = {}
    headers_found = set()

    def _add(ip_norm, header_name, raw_value, hop=None):
        record = records.setdefault(ip_norm, {
            "ip": ip_norm,
            "version": None,
            "type": None,
            "is_public": False,
            "is_valid": True,
            "sources": [],
        })
        source = {"header": header_name, "raw": (raw_value or "").strip()[:500]}
        if hop is not None:
            source["hop"] = hop
        # De-duplicate identical sources.
        for existing in record["sources"]:
            if existing == source:
                return
        record["sources"].append(source)
        headers_found.add(header_name)

    def _scan_header(header_name, value):
        for candidate in _candidates_in(value):
            parsed = parse_ip(candidate)
            if parsed is None:
                continue
            normalized = str(parsed)
            if normalized and not (parsed.is_unspecified and normalized == "::"):
                _add(normalized, header_name, value)

    # Merge raw Received headers into received_headers if not already present
    norm_received = {" ".join(h.split()) for h in received_headers}
    raw_non_received = []
    for h_name, h_val in raw_headers:
        if h_name == "Received":
            n_val = " ".join(h_val.split())
            if n_val not in norm_received:
                received_headers.append(h_val)
                norm_received.add(n_val)
        else:
            raw_non_received.append((h_name, h_val))

    # Received headers: order preserved so hop position is meaningful.
    for hop, header in enumerate(received_headers):
        raw = str(header)
        for candidate in _candidates_in(raw):
            parsed = parse_ip(candidate)
            if parsed is None:
                continue
            _add(str(parsed), "Received", raw, hop=hop)

    if hasattr(msg, "get_all") and msg is not None:
        for name, _desc in IP_SOURCE_HEADERS.items():
            if name == "Received":
                continue
            for value in (msg.get_all(name) or []):
                if value:
                    _scan_header(name, str(value))

        present_headers = {k.lower() for k, _ in msg.items()}
        for name in _EXTRA_IP_HEADERS:
            if name.lower() in present_headers:
                for value in (msg.get_all(name) or []):
                    if value:
                        _scan_header(name, str(value))

    # Also scan raw non-received headers found in text
    for h_name, h_val in raw_non_received:
        _scan_header(h_name, h_val)

    # Classify every unique IP and sort (public first, then by version/ip).
    from utils.ip_utils import classify_ip
    ip_list = []
    for norm, record in records.items():
        cls = classify_ip(norm)
        record["version"] = cls["version"]
        record["type"] = cls["type"]
        record["subtype"] = cls["subtype"]
        record["is_public"] = cls["is_public"]
        ip_list.append(record)

    ip_list.sort(key=lambda r: (not r["is_public"], r["ip"]))

    return {
        "email_id": email_id,
        "parse_error": parse_error,
        "total_ips": len(ip_list),
        "no_ip": len(ip_list) == 0,
        "headers_found": sorted(headers_found),
        "ips": ip_list,
    }