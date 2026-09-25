"""
services/auth_validation.py - Live SPF, DKIM and DMARC verification.

Unlike forensic_engine (which only *parses* the receiver's
Authentication-Results header), this module re-verifies authentication itself:

  * SPF   - uses the EARLIEST RELIABLE public IP from the header chain as the
            connecting client and checks it against the SPF record of the
            envelope sender (Return-Path / MAIL FROM).
  * DKIM  - verifies the DKIM-Signature(s) against the public key published in
            DNS for the selector+domain.
  * DMARC - fetches _dmarc.<from-domain>, evaluates policy (none/quarantine/
            reject) and both SPF and DKIM *alignment* against the From domain.

Libraries `pyspf` and `dkimpy` are optional deps (same convention as
python-whois): when missing, structured {"unavailable": ...} results are
returned so the pipeline degrades gracefully.
"""

import os
import re
from email import policy
from email.parser import BytesParser, Parser

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import spf as _spf
    HAS_SPF = True
except ImportError:
    HAS_SPF = False

try:
    import dkim as _dkim
    HAS_DKIM = True
except ImportError:
    HAS_DKIM = False


# ─── Library / config status ─────────────────────────────────────────────────

def library_status() -> dict:
    return {
        "spf": bool(HAS_SPF),
        "dkim": bool(HAS_DKIM),
        "dns": bool(HAS_DNS),
    }


def auth_timeout() -> float:
    try:
        return max(2.0, min(float(os.getenv("AUTH_VALIDATION_TIMEOUT", "8")), 60.0))
    except ValueError:
        return 8.0


# ─── DNS helpers ─────────────────────────────────────────────────────────────

def resolve_txt(domain: str) -> list:
    """Return TXT record strings for a domain (never raises)."""
    if not HAS_DNS:
        raise RuntimeError("dnspython not installed")
    values = []
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=auth_timeout())
        for r in answers:
            parts = b"".join(s.encode() if isinstance(s, str) else s
                             for s in r.strings).decode("utf-8", errors="ignore")
            values.append(parts)
    except Exception:
        pass
    return values


def _spf_record(domain: str) -> str:
    for txt in resolve_txt(domain):
        if txt.strip().lower().startswith("v=spf1"):
            return txt
    return ""


# ─── Organizational-domain comparison (DMARC alignment) ──────────────────────

# Tiny public-suffix subset for common multi-label TLDs (relaxed alignment).
_MULTI_LABEL_TLDS = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "school.uk",
    "com.au", "net.au", "org.au", "co.nz", "net.nz", "org.nz", "co.in",
    "net.in", "org.in", "co.jp", "ne.jp", "co.za", "com.br", "com.mx",
    "com.mx", "co.id", "co.th", "com.sg", "com.hk", "com.tr", "co.kr",
    "com.cn", "org.cn", "co.il", "com.ph", "com.pe",
}


def organizational_domain(domain: str) -> str:
    """Extract the registrable organizational domain for relaxed alignment."""
    if not domain:
        return ""
    labels = domain.strip().lower().split(".")
    if len(labels) <= 2:
        return domain.strip().lower()
    last2 = ".".join(labels[-2:])
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_TLDS:
        return ".".join(labels[-3:])
    return last2


# ─── SPF ─────────────────────────────────────────────────────────────────────

def validate_spf(client_ip: str, envelope_sender: str, helo: str = "") -> dict:
    """
    Live SPF check of `envelope_sender` for `client_ip`.

    Returns:
        {ok, result, verified, mechanism, explanation, unavailable?}
        verified: True on 'pass', False on 'fail', None otherwise.
    """
    if not HAS_SPF:
        return {
            "ok": False, "unavailable": "pyspf not installed",
            "result": None, "verified": None, "mechanism": None, "explanation": None,
        }
    if not client_ip:
        return {
            "ok": False, "unavailable": "no usable public client IP",
            "result": None, "verified": None, "mechanism": None, "explanation": None,
        }
    if not envelope_sender:
        return {
            "ok": False, "unavailable": "no envelope sender",
            "result": None, "verified": None, "mechanism": None, "explanation": None,
        }
    try:
        result, explanation = _spf.check2(
            i=client_ip, s=envelope_sender, h=(helo or ""))
        mechanism = None
        verified = None
        if result == "pass":
            verified = True
        elif result == "fail":
            verified = False
        return {
            "ok": True,
            "result": result,
            "verified": verified,
            "mechanism": explanation,
            "explanation": f"SPF {result} ({explanation})",
        }
    except Exception as exc:
        return {
            "ok": False, "unavailable": f"SPF evaluation error: {exc}",
            "result": "temperror", "verified": None, "mechanism": None,
            "explanation": str(exc),
        }


# ─── DKIM ────────────────────────────────────────────────────────────────────

def _dkim_signatures(raw_bytes: bytes) -> list:
    """Parse DKIM-Signature headers: list of {domain, selector, raw}."""
    sigs = []
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        for value in msg.get_all("DKIM-Signature") or []:
            text = str(value)
            d = re.search(r"\bd=([^;\s]+)", text)
            s = re.search(r"\bs=([^;\s]+)", text)
            sigs.append({
                "domain": d.group(1) if d else None,
                "selector": s.group(1) if s else None,
                "raw": text[:200],
            })
    except Exception:
        pass
    return sigs


def validate_dkim(raw_bytes: bytes) -> dict:
    """Verify DKIM signature(s) against the public key published in DNS."""
    if not HAS_DKIM:
        return {
            "ok": False, "unavailable": "dkimpy not installed",
            "verified": None, "signatures": [],
        }
    if not raw_bytes:
        return {
            "ok": False, "unavailable": "no raw message bytes",
            "verified": None, "signatures": [],
        }
    try:
        verified = bool(_dkim.verify(raw_bytes))
    except Exception as exc:
        return {
            "ok": False, "unavailable": f"DKIM verification error: {exc}",
            "verified": None, "signatures": _dkim_signatures(raw_bytes),
        }
    return {
        "ok": True,
        "verified": verified,
        "signatures": _dkim_signatures(raw_bytes),
        "explanation": ("DKIM signature verified"
                        if verified else "DKIM signature verification FAILED"),
    }


# ─── DMARC ───────────────────────────────────────────────────────────────────

def _parse_dmarc_record(txt: str) -> dict:
    tags = {}
    for part in txt.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        tags[k.strip().lower()] = v.strip().lower()
    return {
        "raw": txt,
        "version": tags.get("v", ""),
        "policy": tags.get("p", "none"),
        "subdomain_policy": tags.get("sp"),
        "alignment_spf": tags.get("aspf", "r"),
        "alignment_dkim": tags.get("adkim", "r"),
        "pct": int(tags.get("pct", "100") or 100) if str(
            tags.get("pct", "100") or 100).isdigit() else 100,
        "report_uri": tags.get("rua") or tags.get("ruf"),
    }


def _aligned(spf_verified, spf_envelope_domain, dkim_verified, dkim_domain,
             from_domain, mode="relaxed") -> dict:
    """Return DMARC alignment state for SPF and DKIM paths."""
    from_org = organizational_domain(from_domain)

    spf_align = False
    dkim_align = False
    if spf_verified and spf_envelope_domain:
        env_org = organizational_domain(spf_envelope_domain)
        if mode == "strict":
            spf_align = spf_envelope_domain.lower() == from_domain.lower()
        else:
            spf_align = env_org == from_org

    if dkim_verified and dkim_domain:
        dk_org = organizational_domain(dkim_domain)
        if mode == "strict":
            dkim_align = dkim_domain.lower() == from_domain.lower()
        else:
            dkim_align = dk_org == from_org

    return {"spf_aligned": spf_align, "dkim_aligned": dkim_align,
            "any_pass": spf_align or dkim_align}


def validate_dmarc(from_domain: str, spf_result=None, dkim_verified=None,
                   dkim_domain=None, spf_envelope_domain=None) -> dict:
    """
    Evaluate DMARC for `from_domain` given SPF/DKIM outcomes.

    Returns:
        {record, policy, aligned, pass, outcome, explanation}
        outcome: pass | fail | none | no_record | error
    """
    record_txt = ""
    for txt in resolve_txt(f"_dmarc.{from_domain}"):
        if txt.strip().lower().startswith("v=dmarc1"):
            record_txt = txt
            break

    if not record_txt:
        return {
            "ok": False, "outcome": "no_record", "pass": None,
            "policy": "none", "record": "", "explanation":
            "No DMARC policy published for the From domain."
        }

    rec = _parse_dmarc_record(record_txt)
    policy_ = rec["policy"]
    if rec["pct"] < 100:
        policy_ = f"{policy_} ({rec['pct']}% sampling)"

    mode = "strict" if (rec["alignment_spf"] or "") == "s" else "relaxed"
    alignment = _aligned(
        spf_verified=(spf_result or {}).get("verified"),
        spf_envelope_domain=spf_envelope_domain,
        dkim_verified=dkim_verified,
        dkim_domain=dkim_domain,
        from_domain=from_domain,
        mode=mode,
    )

    spf_pass = alignment["spf_aligned"] or (
        (spf_result or {}).get("verified") is True and
        organizational_domain(spf_envelope_domain or "") ==
        organizational_domain(from_domain)
    )
    dkim_pass = alignment["dkim_aligned"] or False
    overall_pass = bool(spf_pass or dkim_pass)

    if overall_pass:
        outcome = "pass"
    elif rec["policy"] == "reject":
        outcome = "fail_reject"
    elif rec["policy"] == "quarantine":
        outcome = "fail_quarantine"
    else:
        outcome = "fail_monitor"

    return {
        "ok": True,
        "record": rec,
        "policy": policy_,
        "alignment": {**alignment,
                      "mode": mode,
                      "spf_pass": spf_pass, "dkim_pass": dkim_pass},
        "pass": overall_pass,
        "outcome": outcome,
        "explanation": (
            f"DMARC {outcome} - policy '{rec['policy']}' | "
            f"SPF aligned={spf_pass} DKIM aligned={dkim_pass}"),
    }


# ─── End-to-end ──────────────────────────────────────────────────────────────

def _parse_headers(raw_text: str):
    msg = Parser(policy=policy.default).parsestr(raw_text or "")
    return msg


def authenticate_email(raw=None, bytes_raw=None, client_ip=None,
                       from_email=None, return_path=None) -> dict:
    """
    Full live authentication verification for a raw email.

    Args:
        raw        - raw email text
        bytes_raw  - raw email bytes (preferred for DKIM)
        client_ip  - optional; otherwise derived from header chain origin
        from_email - optional; otherwise parsed from headers
        return_path- optional; otherwise parsed from headers

    Returns a dict with spf/dkim/dmarc sub-results and an aggregate verdict.
    """
    from_email = from_email or ""
    return_path = return_path or ""

    try:
        msg = BytesParser(policy=policy.default).parsebytes(
            bytes_raw if bytes_raw else (raw or "").encode("utf-8", errors="ignore"))
    except Exception:
        msg = Parser(policy=policy.default).parsestr(raw or "")

    if not from_email:
        from_email = str(msg.get("From") or "").strip()
    if not return_path:
        return_path = str(msg.get("Return-Path") or "").strip(".<>")

    m = re.search(r"@([^>\s]+)", from_email)
    from_domain = m.group(1) if m else ""
    m2 = re.search(r"@([^>\s]+)", return_path)
    envelope_domain = m2.group(1) if m2 else from_domain
    envelope_sender = return_path or from_email

    if not client_ip:
        try:
            from services.header_trust import assess_origin
            from services.ip_extractor import extract_ips_from_email
            extraction = extract_ips_from_email(bytes_raw or (raw or ""))
            origin = assess_origin(extraction, [
                {"ip": r["ip"], "is_public": r["is_public"], "geo": None,
                 "sources": r.get("sources", [])} for r in extraction.get("ips", [])
            ])
            client_ip = origin.get("earliest_reliable_ip")
        except Exception:
            client_ip = None

    spf_result = validate_spf(client_ip, envelope_sender)
    dkim_result = validate_dkim(bytes_raw or (raw or "").encode())
    dkim_verified = dkim_result.get("verified") if dkim_result.get("ok") else None
    dkim_domains = [s["domain"] for s in dkim_result.get("signatures", [])
                    if s.get("domain")]
    dkim_domain = dkim_domains[0] if dkim_domains else None

    dmarc_result = validate_dmarc(
        from_domain, spf_result, dkim_verified, dkim_domain, envelope_domain)

    spf_ok = spf_result.get("verified")
    passed = {
        "spf": spf_ok is True,
        "dkim": dkim_verified is True,
        "dmarc": bool(dmarc_result.get("pass")),
    }
    if any(passed.values()):
        overall = "pass"
    elif (spf_ok is False or (dmarc_result.get("outcome") or "").startswith("fail")):
        overall = "fail"
    else:
        overall = "unverified"

    findings = []
    if spf_ok is False:
        findings.append("🔴 Live SPF check FAILED - connecting IP not authorized for the envelope sender")
    elif spf_ok is True:
        findings.append("✅ Live SPF check passed")
    elif spf_result.get("result"):
        findings.append(f"🟡 Live SPF: {spf_result['result']}")
    if dkim_verified is True:
        findings.append("✅ DKIM signature verified against DNS public key")
    elif dkim_verified is False:
        findings.append("🔴 DKIM signature NOT verified")
    d_out = dmarc_result.get("outcome")
    if d_out == "pass":
        findings.append("✅ DMARC evaluation passes")
    elif d_out and d_out.startswith("fail"):
        findings.append(f"🔴 DMARC evaluation {d_out}")
    elif d_out == "no_record":
        findings.append("🟡 No DMARC record published")

    return {
        "from_email": from_email,
        "from_domain": from_domain,
        "envelope_sender": return_path or from_email,
        "envelope_domain": envelope_domain,
        "client_ip": client_ip,
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
        "passed": passed,
        "overall": overall,
        "findings": findings or ["🟡 Authentication could not be conclusively verified"],
        "library_status": library_status(),
    }