"""
tracking/server.py - HTTP listener serving the tracking endpoints.

Run:  python -m tracking.server

Endpoints:
    GET /health                      -> {"status": "ok", "active_tokens": N}
    GET /track/<token>/pixel.gif     -> 1x1 GIF, logs an *open* interaction
    GET /redir/<token>?u=<target>    -> 302 redirect, logs a *click* interaction
    GET /tokens                      -> JSON list of all tokens (API-token guarded)
    GET /hits/<token>                -> JSON interaction history (API-token guarded)
    GET /hits                        -> JSON combined interaction log (API-token guarded)
"""

import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from tracking.tracker import (PIXEL_GIF, TrackerStore, _real_ip,
                              enrich_request)

_HOST = os.getenv("TRACKING_HOST", "0.0.0.0")
_PORT = int(os.getenv("TRACKING_PORT", "8081"))
_API_TOKEN = os.getenv("TRACKING_API_TOKEN", "")

_store = TrackerStore()
_store_lock = threading.Lock()


def _autorized(handler) -> bool:
    """Bearer-token auth for analyst endpoints (disabled when unset)."""
    if not _API_TOKEN:
        return True
    auth = handler.headers.get("Authorization", "")
    return auth == f"Bearer {_API_TOKEN}"


class TrackingHandler(BaseHTTPRequestHandler):
    server_version = "PhishingTracker/1.0"

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _deny(self):
        self._json(403, {"status": "unauthorized"})

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        path = urlparse(self.path)
        route = path.path

        if route == "/health":
            with _store_lock:
                n = len(_store.tokens())
            self._json(200, {"status": "ok", "active_tokens": n})
            return

        if route.startswith("/track/"):
            m = re.fullmatch(r"/track/([0-9a-f]{32})/pixel\.gif", route)
            if not m:
                self._json(404, {"status": "not_found"})
                return
            token = m.group(1)
            with _store_lock:
                meta = _store.get(token)
                if not meta:
                    self._json(404, {"status": "unknown_token"})
                    return
                ip = _real_ip(self.client_address[0])
                enrichment = enrich_request(ip) if ip else {"error": "no ip"}
                _store.log_event(
                    token=token, kind="open", ip=ip,
                    user_agent=self.headers.get("User-Agent", ""),
                    referer=self.headers.get("Referer", ""),
                    enrichment=enrichment)
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(PIXEL_GIF)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(PIXEL_GIF)
            return

        if route.startswith("/redir/"):
            m = re.fullmatch(r"/redir/([0-9a-f]{32})", route)
            if not m:
                self._json(404, {"status": "not_found"})
                return
            token = m.group(1)
            target = parse_qs(urlparse(self.path).query).get("u", [""])[0]
            with _store_lock:
                meta = _store.get(token)
                if not meta:
                    self._json(404, {"status": "unknown_token"})
                    return
                ip = _real_ip(self.client_address[0])
                enrichment = enrich_request(ip) if ip else {"error": "no ip"}
                _store.log_event(
                    token=token, kind="click", ip=ip,
                    user_agent=self.headers.get("User-Agent", ""),
                    referer=self.headers.get("Referer", ""),
                    enrichment=enrichment)
            self.send_response(302)
            self.send_header("Location", target or "/")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return

        if route in ("/tokens", "/hits"):
            if not _autorized(self):
                return self._deny()
            with _store_lock:
                if route == "/tokens":
                    payload = {"tokens": _store.tokens()}
                else:
                    payload = {"events": _store.hits()}
            self._json(200, payload)
            return

        if route.startswith("/hits/"):
            if not _autorized(self):
                return self._deny()
            token = route.split("/")[-1]
            with _store_lock:
                payload = {"token": token, "events": _store.events(token)}
            self._json(200, payload)
            return

        self._json(404, {"status": "not_found"})


def run_server(host=_HOST, port=_PORT):
    httpd = ThreadingHTTPServer((host, port), TrackingHandler)
    print(f"[tracking] listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[tracking] shutting down")


if __name__ == "__main__":
    run_server()