"""
forensic_engine.py - Forensic Intelligence Engine
Provides email header analysis, WHOIS lookups, SSL certificate inspection,
and domain reputation scoring for threat investigation.
"""

import re
import ssl
import socket
from datetime import datetime, timezone
from email import policy
from email.parser import Parser

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# ─── Email Header Forensics ───────────────────────────────────────────────────

def parse_email_headers(raw_text: str) -> dict:
    """
    Parse raw email text to extract headers and body.
    Handles both raw headers and full email content.

    Returns a dict keyed by header name (only headers that were present),
    plus internal keys:
        Received_All    - the routing chain, in delivered order
        _all_headers    - the full list of (name, value) header pairs
        _has_headers    - True when the input actually contained envelope headers
        _n_from         - number of From header occurrences
        _raw_headers    - unprocessed header block
        _body           - message body (unused by analysis - header forensics
                          is intentionally header-only)
    """
    msg = Parser(policy=policy.default).parsestr(raw_text)

    headers = {}
    header_names = [
        "From", "Sender", "To", "Cc", "Bcc", "Subject", "Date",
        "Message-ID", "Reply-To", "Return-Path", "Received",
        "Envelope-To", "Delivered-To", "X-Original-To", "X-Envelope-From",
        "Resent-From", "List-Id",
        "X-Mailer", "X-Originating-IP", "X-Sender", "X-Forwarded-To",
        "Authentication-Results", "DKIM-Signature", "SPF",
        "MIME-Version", "Content-Type", "X-Priority",
        "X-IP", "X-Mailgun-Variables",
    ]

    for name in header_names:
        value = msg.get(name)
        if value:
            headers[name] = str(value)

    headers["_n_from"] = len(msg.get_all("From") or [])
    headers["_all_headers"] = [
        (str(k), str(v)) for k, v in msg.items() if k and v]
    headers["_has_headers"] = bool(headers["_all_headers"])

    # Extract Received headers (routing chain)
    received_headers = []
    for key, value in msg.items():
        if key.lower() == "received":
            received_headers.append(str(value))
    headers["Received_All"] = received_headers

    # Get body (kept for reference; NOT used by the forensic analysis).
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_content()
                break
    else:
        body = msg.get_content()

    headers["_body"] = body
    headers["_raw_headers"] = "\n".join(
        f"{k}: {v}" for k, v in msg.items() if k)

    return headers


def analyze_email_headers(headers: dict) -> dict:
    """
    Perform forensic analysis on email headers.
    Detects spoofing, routing anomalies, and authentication failures.
    """
    findings = []
    score = 0
    forensic_data = {}

    # ── Sender Analysis ──
    from_header = headers.get("From", "")
    from_email = ""
    from_name = ""

    # Extract email from From header
    email_match = re.search(r'<([^>]+)>', from_header)
    if email_match:
        from_email = email_match.group(1)
        from_name = from_header.replace(email_match.group(0), "").strip().strip('"')
    elif "@" in from_header:
        from_email = from_header.strip()

    forensic_data["from_email"] = from_email
    forensic_data["from_name"] = from_name

    # Check domain mismatch in From header
    if from_email:
        sender_domain = from_email.split("@")[-1] if "@" in from_email else ""
        forensic_data["sender_domain"] = sender_domain

        # Check for display name spoofing (name doesn't match email domain)
        if from_name and sender_domain:
            known_domains = ["google", "microsoft", "apple", "amazon", "facebook", "netflix", "paypal", "bank"]
            name_lower = from_name.lower()
            for dk in known_domains:
                if dk in name_lower and dk not in sender_domain.lower():
                    score += 25
                    findings.append(f"🔴 Display name contains '{dk}' but sender domain is '{sender_domain}' — possible spoofing")
                    break

    # ── Reply-To Mismatch ──
    reply_to = headers.get("Reply-To", "")
    if reply_to and from_email:
        reply_domain = re.search(r'@([^>]+)', reply_to)
        if reply_domain:
            rt_domain = reply_domain.group(1).strip()
            if rt_domain != sender_domain:
                score += 20
                findings.append(f"🟠 Reply-To domain ({rt_domain}) differs from sender domain ({sender_domain})")
                forensic_data["reply_to_mismatch"] = True

    # ── Return-Path Check ──
    return_path = headers.get("Return-Path", "")
    if return_path and from_email:
        rp_match = re.search(r'@([^>]+)', return_path)
        if rp_match:
            rp_domain = rp_match.group(1).strip()
            if rp_domain != sender_domain:
                score += 15
                findings.append(f"🟠 Return-Path domain ({rp_domain}) differs from sender domain")

    # ── Received Header Analysis (Routing Chain) ──
    received = headers.get("Received_All", [])
    forensic_data["received_count"] = len(received)

    if received:
        # Check first (originating) and last (final) hops
        first_hop = received[-1] if received else ""
        last_hop = received[0] if received else ""

        # Extract IPs from received headers
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        all_ips = []
        for rh in received:
            ips = re.findall(ip_pattern, rh)
            all_ips.extend(ips)
        forensic_data["routing_ips"] = list(set(all_ips))

        # Check for unusual routing (many hops)
        if len(received) > 8:
            score += 10
            findings.append(f"🟠 Unusual routing chain — {len(received)} Received hops detected")
        elif len(received) > 5:
            findings.append(f"🟡 Routing chain has {len(received)} hops")

        # Check for loopback or private IPs in headers
        for ip in all_ips:
            if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
                findings.append(f"🟡 Private/loopback IP found in routing: {ip}")

    # ── Authentication Results ──
    auth_results = headers.get("Authentication-Results", "")
    if auth_results:
        # SPF check
        if "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower():
            score += 20
            findings.append("🔴 SPF check FAILED — sender IP not authorized for this domain")
            forensic_data["spf_result"] = "fail"
        elif "spf=pass" in auth_results.lower():
            findings.append("✅ SPF check passed")
            forensic_data["spf_result"] = "pass"
        elif "spf=none" in auth_results.lower():
            score += 5
            findings.append("🟡 No SPF record configured for sender domain")
            forensic_data["spf_result"] = "none"

        # DKIM check
        if "dkim=fail" in auth_results.lower():
            score += 15
            findings.append("🔴 DKIM signature verification FAILED")
            forensic_data["dkim_result"] = "fail"
        elif "dkim=pass" in auth_results.lower():
            findings.append("✅ DKIM signature verified")
            forensic_data["dkim_result"] = "pass"
        elif "dkim=none" in auth_results.lower():
            score += 5
            findings.append("🟡 No DKIM signature found")
            forensic_data["dkim_result"] = "none"

        # DMARC check
        if "dmarc=fail" in auth_results.lower():
            score += 15
            findings.append("🔴 DMARC policy check FAILED")
            forensic_data["dmarc_result"] = "fail"
        elif "dmarc=pass" in auth_results.lower():
            findings.append("✅ DMARC policy passed")
            forensic_data["dmarc_result"] = "pass"
        elif "dmarc=none" in auth_results.lower():
            score += 5
            findings.append("🟡 No DMARC policy configured")
            forensic_data["dmarc_result"] = "none"
    else:
        score += 10
        findings.append("🟠 No Authentication-Results header found — email authentication not verified")
        forensic_data["auth_present"] = False

    # ── X-Originating-IP Check ──
    orig_ip = headers.get("X-Originating-IP", "")
    if orig_ip:
        forensic_data["originating_ip"] = orig_ip.strip("[]")

    # ── Message-ID Analysis ──
    msg_id = headers.get("Message-ID", "")
    if msg_id:
        forensic_data["message_id"] = msg_id
        # Check if Message-ID domain matches sender domain
        mid_match = re.search(r'@([^>]+)>', msg_id)
        if mid_match and sender_domain:
            mid_domain = mid_match.group(1).strip().lower()
            sender_lower = sender_domain.lower()
            # Allow subdomains of the sender domain (e.g. mail.example.com for
            # example.com); flag only genuinely unrelated domains.
            unrelated = (mid_domain != sender_lower
                         and not mid_domain.endswith("." + sender_lower)
                         and not sender_lower.endswith("." + mid_domain))
            if unrelated:
                score += 10
                findings.append(f"🟠 Message-ID domain ({mid_domain}) "
                                f"doesn't match sender domain")

    # ── Priority/X-Priority Check ──
    priority = headers.get("X-Priority", "")
    if priority and priority.strip() in ("1", "High"):
        findings.append("🟡 Email marked as high priority (X-Priority: 1) — common in phishing")

    # ── X-Mailer Check ──
    mailer = headers.get("X-Mailer", "")
    if mailer:
        forensic_data["x_mailer"] = mailer
        suspicious_mailers = ["PHPMailer", "SwiftMailer", "Nodemailer", "King Phisher", "SET"]
        for sm in suspicious_mailers:
            if sm.lower() in mailer.lower():
                score += 15
                findings.append(f"🟠 Suspicious email client detected: {mailer}")
                break

    # ── Date Analysis ──
    date_str = headers.get("Date", "")
    if date_str:
        forensic_data["date"] = date_str
        # Check for future dates
        try:
            from email.utils import parsedate_to_datetime
            msg_date = parsedate_to_datetime(date_str)
            now = datetime.now(timezone.utc)
            if msg_date > now:
                score += 10
                findings.append("🟠 Email Date header is in the future")
        except Exception:
            pass

    # ── Envelope & Recipient Structure (To / Cc / Bcc) ──
    to_header = str(headers.get("To") or "")
    cc_header = str(headers.get("Cc") or "")
    bcc_header = str(headers.get("Bcc") or "")
    sender_hdr = str(headers.get("Sender") or "")
    envelope_to = str(headers.get("Envelope-To")
                      or headers.get("Delivered-To")
                      or headers.get("X-Original-To") or "")

    forensic_data["recipients"] = {"to": to_header, "cc": cc_header,
                                   "bcc": bcc_header}
    forensic_data["envelope_to"] = envelope_to

    addr_re = re.compile(r"[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    to_addrs = addr_re.findall(to_header)
    cc_addrs = addr_re.findall(cc_header)

    if not from_email and not to_addrs:
        score += 20
        findings.append("🔴 No From and no To recipients in headers — "
                        "forged or malformed envelope (body-only input has "
                        "no headers to analyze)")
    elif not to_addrs:
        score += 15
        findings.append("🔴 No To recipients present in headers — abnormal "
                        "envelope")
    if bcc_header and bcc_header.strip():
        score += 15
        findings.append("🟠 Bcc header present on a delivered message — Bcc "
                        "is normally stripped at send time; possible forgery "
                        "artifact")
    if cc_header and not to_header:
        score += 8
        findings.append("🟡 Cc present without a To header — unusual envelope")

    if len(to_addrs) + len(cc_addrs) >= 10:
        score += 8
        findings.append(f"🟡 Mass-addressed envelope "
                        f"({len(to_addrs) + len(cc_addrs)} recipients)")

    if from_email:
        lower_from = from_email.lower()
        if any(a.lower() == lower_from for a in to_addrs):
            score += 10
            findings.append("🟡 Email is addressed to its own From address — "
                            "self-sent/automated artifact")
        if any(a.lower() == lower_from for a in cc_addrs):
            score += 6
            findings.append("🟡 From address is also copied on the Cc")

    # Envelope recipient vs sender-domain consistency
    if envelope_to and from_email and sender_domain:
        env_m = re.search(r"@([^>\s]+)", envelope_to)
        if env_m and env_m.group(1).strip().lower() != sender_domain.lower():
            score += 10
            findings.append(f"🟠 Envelope recipient domain "
                            f"({env_m.group(1).strip()}) differs from sender "
                            f"domain ({sender_domain})")
            forensic_data["envelope_recipient_mismatch"] = True

    # Sender header vs From consistency
    if sender_hdr and from_email:
        sen_m = addr_re.search(sender_hdr)
        if sen_m and sen_m.group(0).lower() != from_email.lower():
            score += 12
            findings.append(f"🟠 'Sender' header ({sen_m.group(0)}) differs "
                            f"from 'From' ({from_email})")
            forensic_data["sender_header_mismatch"] = True

    # ── Envelope completeness & forgery artifacts ──
    n_from = int(headers.get("_n_from", 1) or 1)
    if n_from > 1:
        score += 25
        findings.append("🔴 Multiple From headers present — header forgery "
                        "artifact")

    if not msg_id:
        score += 5
        findings.append("🟡 No Message-ID header present")
    if not str(date_str or "").strip():
        score += 5
        findings.append("🟡 No Date header present")

    # CRLF / embedded line-break (header-injection) check on core fields.
    for _hname in ("From", "To", "Cc", "Bcc", "Subject", "Reply-To",
                   "Date", "Message-ID"):
        _hval = str(headers.get(_hname) or "")
        if "\n" in _hval or "\r" in _hval:
            score += 25
            findings.append(f"🔴 Embedded line-break in '{_hname}' header "
                            f"value — CRLF header-injection artifact")
            forensic_data["header_injection"] = True
            break

    score = min(score, 100)

    if not findings:
        findings.append("✅ No forensic anomalies detected in email headers")

    return {
        "score": score,
        "findings": findings,
        "forensic_data": forensic_data,
    }


# ─── WHOIS Domain Intelligence ────────────────────────────────────────────────

def whois_lookup(domain: str) -> dict:
    """
    Perform WHOIS lookup for domain intelligence.
    Returns registrar, creation/expiry dates, name servers, and reputation signals.
    """
    result = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "name_servers": [],
        "registrant_org": None,
        "registrant_country": None,
        "registrant_email": None,
        "status": [],
        "dnssec": None,
        "is_recently_registered": False,
        "is_expired": False,
        "error": None,
    }

    if not HAS_WHOIS:
        result["error"] = "python-whois library not installed"
        return result

    try:
        w = whois.whois(domain)

        result["registrar"] = getattr(w, "registrar", None)
        result["registrant_org"] = getattr(w, "org", None)
        result["registrant_country"] = getattr(w, "country", None)
        
        emails = getattr(w, "emails", None)
        if isinstance(emails, (list, tuple)) and len(emails) > 0:
            result["registrant_email"] = str(emails[0])
        elif emails:
            result["registrant_email"] = str(emails)

        # Name servers
        name_servers = getattr(w, "name_servers", None)
        if name_servers:
            result["name_servers"] = list(set(str(ns).lower() for ns in name_servers if ns))

        # Status
        status = getattr(w, "status", None)
        if status:
            result["status"] = status if isinstance(status, list) else [status]

        # Dates
        creation = getattr(w, "creation_date", None)
        expiration = getattr(w, "expiration_date", None)

        if isinstance(creation, list) and len(creation) > 0:
            creation = creation[0]
        if isinstance(expiration, list) and len(expiration) > 0:
            expiration = expiration[0]

        if creation:
            result["creation_date"] = creation.isoformat() if hasattr(creation, "isoformat") else str(creation)
            if hasattr(creation, "timestamp"):
                try:
                    age_days = (datetime.now() - creation).days
                    result["domain_age_days"] = age_days
                    result["is_recently_registered"] = age_days < 90
                except Exception:
                    pass

        if expiration:
            result["expiration_date"] = expiration.isoformat() if hasattr(expiration, "isoformat") else str(expiration)
            if hasattr(expiration, "timestamp"):
                try:
                    result["is_expired"] = expiration < datetime.now()
                except Exception:
                    pass

    except Exception as e:
        result["error"] = f"WHOIS lookup error: {str(e)}"

    return result


# ─── SSL Certificate Analysis ────────────────────────────────────────────────

def analyze_ssl_certificate(domain: str, port: int = 443) -> dict:
    """
    Analyze the SSL/TLS certificate of a domain.
    Returns issuer, validity, subject, and chain information.
    """
    result = {
        "domain": domain,
        "has_ssl": False,
        "issuer": {},
        "subject": {},
        "not_before": None,
        "not_after": None,
        "serial_number": None,
        "san_domains": [],
        "version": None,
        "is_self_signed": False,
        "is_expired": False,
        "days_until_expiry": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                result["has_ssl"] = True
                result["version"] = ssock.version()

                # Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer_dict

                # Subject
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                result["subject"] = subject_dict

                # Validity
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                result["not_before"] = not_before
                result["not_after"] = not_after

                # Parse dates
                date_formats = ["%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"]
                for fmt in date_formats:
                    try:
                        expiry_dt = datetime.strptime(not_after, fmt)
                        result["is_expired"] = expiry_dt < datetime.now()
                        result["days_until_expiry"] = (expiry_dt - datetime.now()).days
                        break
                    except ValueError:
                        continue

                # Serial number
                result["serial_number"] = cert.get("serialNumber")

                # SAN (Subject Alternative Names)
                san_ext = cert.get("subjectAltName", ())
                result["san_domains"] = [name for typ, name in san_ext if typ == "DNS"]

                # Check if self-signed
                if issuer_dict.get("organizationName") == subject_dict.get("organizationName"):
                    result["is_self_signed"] = True

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL verification failed: {str(e)}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except socket.gaierror:
        result["error"] = "Domain could not be resolved"
    except Exception as e:
        result["error"] = f"SSL analysis failed: {str(e)}"

    return result


# ─── Comprehensive Forensic Report ───────────────────────────────────────────

def generate_forensic_report(
    email_text: str = None,
    domain: str = None,
) -> dict:
    """
    Generate a comprehensive forensic intelligence report.
    Can analyze email headers, domain WHOIS, SSL certificates, and DNS.
    """
    report = {
        "sender_domain": domain,
        "email_forensics": None,
        "whois_data": None,
        "ssl_data": None,
        "dns_data": None,
        "overall_score": 0,
        "risk_level": "safe",
        "findings": [],
    }

    all_findings = []
    all_scores = []

    # Email header analysis
    if email_text:
        try:
            headers = parse_email_headers(email_text)
            email_result = analyze_email_headers(headers)
            report["email_forensics"] = {
                "headers": {k: v for k, v in headers.items() if k != "Received_All" and not k.startswith("_")},
                "has_headers": bool(headers.get("_has_headers")),
                "raw_headers": headers.get("_raw_headers", ""),
                "analysis": email_result,
            }
            all_findings.extend(email_result["findings"])
            all_scores.append(email_result["score"])

            # Use sender domain for WHOIS/SSL if available
            if not domain and email_result["forensic_data"].get("sender_domain"):
                domain = email_result["forensic_data"]["sender_domain"]
            report["sender_domain"] = domain
        except Exception as e:
            report["email_forensics"] = {"error": str(e)}

    # Domain analysis
    if domain:
        # WHOIS
        whois_data = whois_lookup(domain)
        report["whois_data"] = whois_data

        if whois_data.get("is_recently_registered"):
            all_scores.append(30)
            all_findings.append(f"🔴 Domain '{domain}' was registered only {whois_data['domain_age_days']} days ago — very young domain")
        elif whois_data.get("domain_age_days") and whois_data["domain_age_days"] < 365:
            all_scores.append(15)
            all_findings.append(f"🟠 Domain '{domain}' is only {whois_data['domain_age_days']} days old (< 1 year)")
        elif whois_data.get("is_expired"):
            all_scores.append(25)
            all_findings.append(f"🔴 Domain '{domain}' has EXPIRED — likely abandoned or malicious")

        if whois_data.get("error"):
            all_findings.append(f"🟡 WHOIS lookup issue: {whois_data['error']}")

        # SSL Certificate
        ssl_data = analyze_ssl_certificate(domain)
        report["ssl_data"] = ssl_data

        if ssl_data.get("has_ssl"):
            if ssl_data.get("is_self_signed"):
                all_scores.append(15)
                all_findings.append("🟠 SSL certificate is SELF-SIGNED — not issued by a trusted CA")
            elif ssl_data.get("is_expired"):
                all_scores.append(20)
                all_findings.append("🔴 SSL certificate has EXPIRED")
            elif ssl_data.get("days_until_expiry") is not None and ssl_data["days_until_expiry"] < 30:
                all_findings.append(f"🟡 SSL certificate expires in {ssl_data['days_until_expiry']} days")

            # Check for free/shared certificates (common in phishing)
            issuer_org = ssl_data.get("issuer", {}).get("organizationName", "")
            free_cas = ["Let's Encrypt", "ZeroSSL", "cPanel", "Comodo"]
            if any(ca.lower() in issuer_org.lower() for ca in free_cas):
                all_findings.append(f"🟡 SSL issued by {issuer_org} — free certificate (common in phishing)")
        else:
            if ssl_data.get("error"):
                all_findings.append(f"🟠 SSL/TLS: {ssl_data['error']}")

        # DNS (import from geo_engine)
        try:
            from geo_engine import resolve_dns
            dns_data = resolve_dns(domain)
            report["dns_data"] = dns_data

            if not dns_data.get("mx_records") and not dns_data.get("ns_records"):
                all_scores.append(10)
                all_findings.append("🟠 No MX or NS records — domain lacks email infrastructure")
        except ImportError:
            pass

    # Calculate overall score
    if all_scores:
        report["overall_score"] = min(100, max(all_scores))
    report["findings"] = all_findings if all_findings else ["✅ No forensic anomalies detected"]

    # Risk level
    s = report["overall_score"]
    if s >= 60:
        report["risk_level"] = "critical"
    elif s >= 35:
        report["risk_level"] = "high"
    elif s > 10:
        report["risk_level"] = "moderate"
    elif s > 0:
        report["risk_level"] = "low"
    else:
        report["risk_level"] = "safe"

    return report
