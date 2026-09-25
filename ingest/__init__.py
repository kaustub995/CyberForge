"""
ingest/__init__.py - Real-time ingestion & alerting for the detection platform.

Run the webhook listener with:

    python -m ingest.webhook_server

Environment:
    INGEST_HOST (default 0.0.0.0)
    INGEST_PORT (default 8080)
    INGEST_TOKEN (optional bearer token; skip auth when empty)
    SENDER_ALLOWLIST / SENDER_DENYLIST (comma-separated patterns; filtering
        happens BEFORE any content processing)
    ALERT_WEBHOOK_URL (optional) - JSON POST for high-risk alerts
    CASE_STORE_PATH (default data/cases.db)
"""

__all__ = ["run_server", "process_inbound"]