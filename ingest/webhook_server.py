"""
ingest/webhook_server.py - Real-time email ingestion + alerting.

A dependency-free HTTP listener (stdlib http.server) that accepts raw email
text via POST and runs the full pipeline:

    sender filter -> parse/extract -> geo/intel -> forensics -> 5-class verdict
                   -> store (case/campaign) -> alert when high-risk

Endpoints:
    POST /analyze   JSON {"text": "..."} or {"email": "..."} or raw .eml body
    GET  /health    {"status": "ok", "config": ...}

Alerting is pluggable: ALERT_WEBHOOK_URL receives a JSON POST (Slack/Teams/API),
and every payload is also appended to the chain-of-custody log.
"""

import json
import os
import re
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def _env_list(name):
    return [v.strip().lower() for v in os.getenv(name, "").split(",") if v.strip()]


class _IndexedStore:
    """Lazy-constructed persistence so importing this module never touches disk."""

    def __init__(self):
        self.store = None
        self.coc = None

    def _ensure(self):
        if self.store is None:
            from storage.case_store import CaseStore
            from storage.compliance import ChainOfCustodyLogger
            self.store = CaseStore()
            self.coc = ChainOfCustodyLogger()
        return self.store, self.coc


_indexed = _IndexedStore()
_allowlist = _env_list("SENDER_ALLOWLIST")
_denylist = _env_list("SENDER_DENYLIST")
_alert_url = os.getenv("ALERT_WEBHOOK_URL", "").strip()


def _extract_from(raw_text: str) -> str:
    """Pull the From address from raw header text without full parsing."""
    for line in (raw_text or "").splitlines():
        if line.lower().startswith("from:"):
            addr = line[5:].strip()
            m = re.search(r"<([^>]+)>", addr)
            return (m.group(1) if m else addr).strip()
    return ""


def _sender_allowed(from_email: str) -> tuple:
    """Sender filtering runs BEFORE any content processing/analysis."""
    if not from_email:
        return True, ""
    low = from_email.lower()
    if _denylist and any(p in low for p in _denylist):
        return False, f"Sender denied by SENDER_DENYLIST policy ({from_email})"
    if _allowlist and not any(p in low for p in _allowlist):
        return False, f"Sender not in SENDER_ALLOWLIST policy ({from_email})"
    return True, ""


def _fire_alert(payload: dict):
    if not _alert_url:
        return
    try:
        import requests
        requests.post(_alert_url, json=payload, timeout=8)
    except Exception:
        pass  # alerts are best-effort; the custody log still records the event


def process_inbound(raw_text: str, source: str = "webhook", store_raw=True) -> dict:
    """
    Run the full pipeline on raw email text. Returns a structured result dict.
    This is the same pipeline the webhook handler uses, exposed for tests/CLI.
    """
    start = time.time()
    store, coc = _indexed._ensure()

    from_email = _extract_from(raw_text)
    allowed, reason = _sender_allowed(from_email)
    if not allowed:
        coc.log(actor="ingest", event="sender_filtered", detail=reason)
        return {
            "status": "rejected", "reason": reason,
            "from_email": from_email,
            "processed_seconds": round(time.time() - start, 3),
        }

    # Parse + extract
    from services.ip_extractor import extract_ips_from_email
    extraction = extract_ips_from_email(raw_text)
    if extraction.get("parse_error"):
        coc.log(actor="ingest", event="parse_error", detail=extraction["parse_error"])

    # IP intelligence (geo + abuseipdb enrichment)
    from services.ip_analyzer import run_ip_intelligence
    ip_result = run_ip_intelligence(extraction)
    enriched_results = ip_result["ip_results"]
    enriched_summary = ip_result["summary"]

    # Header trust + anomalies
    from services.header_trust import assess_origin, detect_header_anomalies
    origin = assess_origin(extraction, enriched_results)
    anomalies = detect_header_anomalies(extraction)

    # Content + forensics
    from forensic_engine import parse_email_headers, analyze_email_headers
    from utils import analyze_email, analyze_social_engineering, extract_urls, load_model
    headers = parse_email_headers(raw_text)
    forensics = analyze_email_headers(headers)
    model, vectorizer = load_model()
    content = analyze_email(raw_text, model, vectorizer)
    soceng = analyze_social_engineering(
        (headers.get("_body") or "") + " " + (headers.get("Subject") or ""))

    urls = extract_urls(raw_text)

    # 5-class verdict fusing all evidence
    from utils.multiclass import classify_email
    verdict = classify_email(
        rule_score=content.get("rule_score", 0),
        ml_result=content.get("ml_prediction"),
        soceng=soceng,
        forensic={"findings": forensics["findings"],
                  "forensic_data": forensics.get("forensic_data", {})},
        ip_summary=enriched_summary,
        urls=urls,
    )

    result = {
        "status": "analyzed",
        "email_id": extraction.get("email_id"),
        "from_email": from_email,
        "sender_domain": verdict.get("sender_domain"),
        "verdict_class": verdict["class"],
        "verdict_priority": verdict["priority"],
        "inbox_score": content.get("combined_score"),
        "soceng_risk": soceng.get("overall_risk"),
        "forensic_score": forensics.get("score"),
        "ip_risk": enriched_summary.get("risk_level"),
        "origin_assessment": origin.get("assessment"),
        "origin_summary": origin.get("summary"),
        "origin_first_reliable_ip": origin.get("earliest_reliable_ip"),
        "anomalies": anomalies,
        "reasons": verdict["reasons"],
        "campaign_id": None,
        "stored": False,
        "processed_seconds": round(time.time() - start, 3),
    }

    if store_raw:
        record = store.store_email(
            email_id=result["email_id"],
            verdict_class=verdict["class"],
            verdict_priority=verdict["priority"],
            combined_score=content.get("combined_score"),
            ip_risk=enriched_summary.get("risk_level"),
            from_email=from_email,
            sender_domain=verdict.get("sender_domain"),
            subject=headers.get("Subject") or "",
            received_at=headers.get("Date") or "",
            urls=urls,
            ips=[r["ip"] for r in enriched_results],
            raw_headers=headers.get("_raw_headers") or "",
            body_text=headers.get("_body") or "",
        )
        result["stored"] = True
        result["campaign_id"] = record.get("campaign_id")
        coc.log(actor="ingest",
                event=f"stored_verdict:{verdict['class']}",
                detail=f"email_id={result['email_id']} "
                       f"campaign={record.get('campaign_id')} "
                       f"origin={origin.get('assessment')}")

    if verdict["priority"] in ("high", "critical"):
        _fire_alert({k: v for k, v in result.items()
                     if k not in ("anomalies", "reasons", "origin_summary")})
        coc.log(actor="ingest", event="alert_high_risk",
                detail=f"email_id={result['email_id']} class={verdict['class']}")

    return result


def _max_risk(levels):
    order = {"clean": 0, "low": 1, "moderate": 2, "high": 3}
    return max(levels, key=lambda l: order.get(l, 0))


class _Handler(BaseHTTPRequestHandler):
    server_version = "CyberForgeIngest/1.0"

    def _auth_ok(self):
        token = os.getenv("INGEST_TOKEN", "").strip()
        if not token:
            return True
        return self.headers.get("Authorization", "").replace("Bearer ", "") == token

    def _send_json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?")[0] == "/health":
            from services.geoip_service import get_geoip_config
            from services.threat_intel import get_threat_intel_config
            self._send_json(200, {
                "status": "ok",
                "geoip": get_geoip_config()["enabled"],
                "threat_intel": get_threat_intel_config()["enabled"],
                "store_path": os.getenv("CASE_STORE_PATH", "data/cases.db"),
            })
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?")[0] != "/analyze":
            self._send_json(404, {"error": "not found"})
            return
        if not self._auth_ok():
            self._send_json(401, {"error": "unauthorized"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
        except Exception:
            body = b""

        text = ""
        try:
            parsed = json.loads(body) if body else {}
            if isinstance(parsed, dict):
                text = parsed.get("text") or parsed.get("email") or ""
        except ValueError:
            text = body.decode("utf-8", errors="ignore")

        if not text.strip():
            self._send_json(400, {"error": "empty email payload"})
            return

        result = process_inbound(text, source="webhook")
        code = 202 if result["status"] in ("analyzed",) else 200
        self._send_json(code, result)


def run_server(host=None, port=None, **kw):
    host = host or os.getenv("INGEST_HOST", "0.0.0.0")
    port = int(port or os.getenv("INGEST_PORT", "8080"))
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"[ingest] CyberForge webhook listening on http://{host}:{port} "
          "POST /analyze | GET /health")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[ingest] stopping")
        httpd.server_close()


if __name__ == "__main__":
    run_server()