"""
tracking/__init__.py - Active tracking: pixel tokens + click redirects.

Run the tracking listener with:

    python -m tracking.server

Environment:
    TRACKING_HOST / TRACKING_PORT   (default 0.0.0.0 / 8081)
    TRACKING_BASE_URL               (default http://localhost:8081) - used to build
                                    embeddable pixel / redirect URLs
    TRACKING_API_TOKEN              (optional) bearer required for /tokens and /hits
    TRACKING_DB_PATH                (default data/cases.db)

Flow:
    1. mint_email_token(email_id, campaign_id) -> token
    2. open_url(token) / redirect_url(token, target) -> URLs to embed in an
       outbound (honeypot) email body.
    3. When the recipient interacts, their real IP + UA + referer are captured
       and enriched (geo-IP + RDAP registry + reverse DNS) on the fly.
"""

__all__ = ["mint_email_token", "open_url", "redirect_url", "TrackerStore"]