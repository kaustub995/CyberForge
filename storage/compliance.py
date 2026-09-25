"""
storage/compliance.py - Privacy & evidentiary safeguards.

  * mask_pii()             - irreversible masking of emails, phones, cards, SSNs.
  * ChainOfCustodyLogger   - tamper-evident append-only audit log (hash chain +
                             HMAC signature) for investigation/legal support.
  * purge_older_than()     - configurable retention: drop stored evidence older
                             than N days.
"""

import hashlib
import hmac
import os
import re
import sqlite3
import time

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d{1,3}[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}(?!\d)")
_CARD_RE = re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)")
_SSN_RE = re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b")


def mask_pii(text: str) -> str:
    """Return a copy of `text` with personal/secret data masked with [REDACTED]."""
    if not text:
        return text or ""
    masked = text
    masked = _EMAIL_RE.sub("[REDACTED_EMAIL]", masked)
    masked = _PHONE_RE.sub("[REDACTED_PHONE]", masked)
    masked = _CARD_RE.sub("[REDACTED_CARD]", masked)
    masked = _SSN_RE.sub("[REDACTED_SSN]", masked)
    return masked


class ChainOfCustodyLogger:
    """
    Append-only, signed audit log stored in its own SQLite table.

    Every entry carries the previous entry's hash and an HMAC keyed by
    COC_SECRET (or a stable file fallback). verify() recomputes the chain and
    HMACs so any tampering with historical rows is detected.
    """

    def __init__(self, db_path: str = None, secret: str = None):
        self.db_path = db_path or os.getenv("CASE_STORE_PATH", "data/cases.db")
        self._secret = (secret or os.getenv("COC_SECRET", "coc-dev-secret-change-me")).encode("utf-8")
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS custody_chain (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               ts TEXT NOT NULL,
               actor TEXT,
               event TEXT NOT NULL,
               detail TEXT,
               prev_hash TEXT,
               entry_hash TEXT NOT NULL,
               hmac_sig TEXT NOT NULL
            )"""
        )
        self._conn.commit()

    def log(self, actor: str, event: str, detail: str = "") -> str:
        """Append a signed entry; returns its entry_hash."""
        prev = self._conn.execute(
            "SELECT entry_hash FROM custody_chain ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = prev["entry_hash"] if prev else ""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = f"{ts}|{actor}|{event}|{detail}|{prev_hash}"
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        sig = hmac.new(self._secret, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        self._conn.execute(
            "INSERT INTO custody_chain (ts, actor, event, detail, prev_hash, entry_hash, hmac_sig) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, actor, event, detail, prev_hash, entry_hash, sig),
        )
        self._conn.commit()
        return entry_hash

    def entries(self, limit=100) -> list:
        rows = self._conn.execute(
            "SELECT * FROM custody_chain ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def verify(self) -> dict:
        """Recompute the hash chain + signatures; report any break."""
        rows = self._conn.execute(
            "SELECT * FROM custody_chain ORDER BY id ASC"
        ).fetchall()
        broken = []
        prev_hash = ""
        for row in rows:
            ts, actor, event, detail = row["ts"], row["actor"], row["event"], row["detail"]
            payload = f"{ts}|{actor}|{event}|{detail}|{prev_hash}"
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if expected != row["entry_hash"]:
                broken.append((row["id"], "hash_mismatch"))
            sig = hmac.new(self._secret, row["entry_hash"].encode("utf-8"),
                           hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, row["hmac_sig"]):
                broken.append((row["id"], "sig_mismatch"))
            prev_hash = row["entry_hash"]
        return {
            "entries": len(rows),
            "intact": len(broken) == 0,
            "issues": broken,
        }


def purge_older_than(db_path: str, days: int, dry_run=False) -> dict:
    """Delete stored emails/cases from case_store paths older than `days` days.

    Only rows whose stored_at is older than the retention window are removed
    (retention enforcement). Returns counts.
    """
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                           time.gmtime(time.time() - days * 86400))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id FROM emails WHERE stored_at < ?", (cutoff,)
    ).fetchall()
    email_ids = [r["id"] for r in rows]
    ids_to_purge = [r["id"] for r in rows]
    count = len(ids_to_purge)
    if not dry_run and count:
        conn.execute("DELETE FROM emails WHERE id IN (%s)" % ",".join("?" * count), ids_to_purge)
        conn.commit()
    conn.close()
    return {"purged": count, "cutoff": cutoff, "retention_days": days, "dry_run": dry_run}