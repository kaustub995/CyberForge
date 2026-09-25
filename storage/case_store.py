"""
storage/case_store.py - SQLite-backed case & campaign store.

Stores analyzed emails with masked content, extracted indicators, verdicts and
the evidence chain needed to group related fraudulent emails into campaigns.

Features:
  * deterministic hashing of the raw source (sha256) - raw bodies are never
    stored unless retention/masking policy allows it;
  * indicator-level campaign grouping (shared domain, IP, URL, sender);
  * cross-email campaign detection with a stable campaign id;
  * recent-email search + campaign listing for the dashboard/webhook reports.
"""

import hashlib
import os
import re
import sqlite3
import time
from urllib.parse import urlparse

from .compliance import mask_pii

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(r"https?://[^\s<>\"']+")


class CaseStoreError(Exception):
    """Raised for storage-level problems (bad schema, IO, locked db)."""


def sha256_hex(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()


def extract_indicators(from_email="", sender_domain="", urls=None, ips=None) -> list:
    """Turn a parsed email record into a flat list of (kind, value, risk) rows."""
    indicators = []
    if from_email:
        indicators.append(("email", from_email.lower(), "sender"))
    if sender_domain:
        indicators.append(("domain", sender_domain.lower(), "sender_domain"))
    for url in urls or []:
        indicators.append(("url", str(url), "link"))
        host = urlparse(str(url)).netloc.lower()
        if host:
            indicators.append(("domain", host, "url_host"))
    for ip in ips or []:
        indicators.append(("ip", str(ip), "routing"))
    return indicators


class CaseStore:
    """Run it as a context manager or call close() explicitly."""

    def __init__(self, path: str = None):
        self.path = path or os.getenv("CASE_STORE_PATH", "data/cases.db")
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self._conn = None
        self.open()

    def open(self):
        try:
            self._conn = sqlite3.connect(self.path)
            self._conn.row_factory = sqlite3.Row
            self._schema()
        except sqlite3.Error as exc:
            raise CaseStoreError(f"Could not open case store {self.path}: {exc}") from exc

    def close(self):
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def _conn_checked(self):
        if self._conn is None:
            self.open()
        return self._conn

    def _schema(self):
        conn = self._conn_checked()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                from_email TEXT,
                sender_domain TEXT,
                subject TEXT,
                received_at TEXT,
                verdict_class TEXT,
                verdict_priority TEXT,
                combined_score REAL,
                ip_risk TEXT,
                raw_headers TEXT,
                body_masked TEXT,
                stored_at TEXT
            );
            CREATE TABLE IF NOT EXISTS indicators (
                email_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                role TEXT
            );
            CREATE TABLE IF NOT EXISTS cases (
                campaign_id TEXT NOT NULL,
                email_id TEXT NOT NULL,
                opened_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ind_email ON indicators(email_id);
            CREATE INDEX IF NOT EXISTS idx_ind_kind_value ON indicators(kind, value);
            CREATE INDEX IF NOT EXISTS idx_email_sha ON emails(sha256);
            CREATE INDEX IF NOT EXISTS idx_case_campaign ON cases(campaign_id);
            """
        )
        conn.commit()

    # ── Ingestion ──────────────────────────────────────────────────────────

    def store_email(self, email_id, verdict_class="unknown", verdict_priority="normal",
                    combined_score=None, ip_risk=None, from_email="", sender_domain="",
                    subject="", received_at=None, urls=None, ips=None,
                    raw_headers=None, body_text=None, mask=True) -> dict:
        """
        Store one analyzed email (PII-masked) plus its indicators.

        Returns the stored record dict (with campaign info).
        """
        conn = self._conn_checked()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        received_at = received_at or now
        body_masked = mask_pii(body_text or "") if mask else (body_text or "")
        raw_headers = raw_headers or ""

        row = {
            "email_id": email_id or sha256_hex(from_email or "")[:16],
            "sha256": sha256_hex((raw_headers or "") + (body_text or "")),
            "from_email": from_email,
            "sender_domain": sender_domain,
            "subject": subject,
            "received_at": received_at,
            "verdict_class": verdict_class,
            "verdict_priority": verdict_priority,
            "combined_score": combined_score,
            "ip_risk": ip_risk,
            "raw_headers": raw_headers,
            "body_masked": body_masked,
            "stored_at": now,
        }
        try:
            cursor = conn.execute(
                """INSERT INTO emails
                   (email_id, sha256, from_email, sender_domain, subject,
                    received_at, verdict_class, verdict_priority, combined_score,
                    ip_risk, raw_headers, body_masked, stored_at)
                   VALUES (:email_id, :sha256, :from_email, :sender_domain, :subject,
                           :received_at, :verdict_class, :verdict_priority,
                           :combined_score, :ip_risk, :raw_headers, :body_masked,
                           :stored_at)""",
                row,
            )
            row["id"] = cursor.lastrowid

            for kind, value, role in extract_indicators(
                    from_email=from_email, sender_domain=sender_domain,
                    urls=urls, ips=ips):
                conn.execute(
                    "INSERT INTO indicators (email_id, kind, value, role) "
                    "VALUES (?, ?, ?, ?)", (row["email_id"], kind, value, role))

            campaign_id = self._find_or_assign_campaign(row["email_id"])
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise CaseStoreError(f"store_email failed: {exc}") from exc
        row["campaign_id"] = campaign_id
        return row

    def _find_or_assign_campaign(self, email_id: str) -> str:
        """Group emails that share any indicator value (or sender_domain)."""
        conn = self._conn_checked()
        rows = conn.execute(
            "SELECT i.value FROM indicators i WHERE i.email_id = ?", (email_id,)
        ).fetchall()
        values = [r["value"] for r in rows]
        existing = conn.execute(
            """SELECT c.campaign_id FROM cases c
               JOIN indicators i ON i.email_id = c.email_id
               WHERE i.value IN (%s) LIMIT 1"""
            % ",".join("?" * len(values)), values
        ).fetchone() if values else None
        if existing is not None:
            campaign_id = existing["campaign_id"]
        else:
            campaign_id = f"cmp-{sha256_hex(email_id + str(time.time()))[:10]}"
        conn.execute(
            "INSERT INTO cases (campaign_id, email_id, opened_at) VALUES (?, ?, ?)",
            (campaign_id, email_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
        return campaign_id

    # ── Queries ─────────────────────────────────────────────────────────────

    def list_emails(self, limit=50, offset=0) -> list:
        conn = self._conn_checked()
        rows = conn.execute(
            """SELECT e.id, e.email_id, e.from_email, e.sender_domain, e.subject,
                      e.verdict_class, e.verdict_priority, e.combined_score,
                      e.ip_risk, e.stored_at
               FROM emails e ORDER BY e.id DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_campaigns(self, limit=50) -> list:
        conn = self._conn_checked()
        rows = conn.execute(
            """SELECT c.campaign_id, COUNT(DISTINCT c.email_id) AS email_count,
                      GROUP_CONCAT(DISTINCT e.verdict_class) AS verdicts,
                      MAX(e.stored_at) AS last_seen
               FROM cases c JOIN emails e ON e.email_id = c.email_id
               GROUP BY c.campaign_id ORDER BY last_seen DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_campaign_emails(self, campaign_id: str) -> list:
        conn = self._conn_checked()
        rows = conn.execute(
            """SELECT e.email_id, e.from_email, e.sender_domain, e.subject,
                      e.verdict_class, e.combined_score, e.stored_at
               FROM cases c JOIN emails e ON e.email_id = c.email_id
               WHERE c.campaign_id = ? ORDER BY e.stored_at DESC""",
            (campaign_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def search(self, query: str, limit=50) -> list:
        q = f"%{query}%"
        conn = self._conn_checked()
        rows = conn.execute(
            """SELECT e.id, e.email_id, e.from_email, e.sender_domain, e.subject,
                      e.verdict_class, e.combined_score, e.stored_at
               FROM emails e
               WHERE e.email_id LIKE ? OR e.from_email LIKE ? OR
                     e.sender_domain LIKE ? OR e.subject LIKE ?
               ORDER BY e.id DESC LIMIT ?""",
            (q, q, q, q, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def email_indicators(self, email_id: str) -> list:
        conn = self._conn_checked()
        rows = conn.execute(
            "SELECT kind, value, role FROM indicators WHERE email_id = ?",
            (email_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        conn = self._conn_checked()
        emails = conn.execute("SELECT COUNT(*) AS n FROM emails").fetchone()["n"]
        campaigns = conn.execute(
            "SELECT COUNT(DISTINCT campaign_id) AS n FROM cases").fetchone()["n"]
        high = conn.execute(
            "SELECT COUNT(*) AS n FROM emails WHERE verdict_priority IN ('high','critical')"
        ).fetchone()["n"]
        return {"emails": emails, "campaigns": campaigns, "high_risk": high}