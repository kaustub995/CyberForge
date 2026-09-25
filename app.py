"""
app.py - AI-Based Phishing Email Detection System
A Streamlit application that combines rule-based analysis with ML classification
to detect phishing emails. Features a cyberpunk/tech aesthetic with animated UI.
"""

import streamlit as st
import os
import time
import json
from datetime import datetime
import pandas as pd
import plotly.graph_objects as go
from utils import analyze_email, analyze_url, analyze_social_engineering, load_model, extract_urls, normalize_url_or_domain  # noqa: E402
from utils.eml_parser import parse_eml_file  # noqa: E402
from geo_engine import geolocate_domain, generate_map_data, assess_geo_threat, resolve_dns, build_geolocation_map_figure  # noqa: E402
from forensic_engine import generate_forensic_report  # noqa: E402
from services.ip_extractor import extract_ips_from_email  # noqa: E402
from services.ip_analyzer import run_ip_intelligence  # noqa: E402
from services.geoip_service import get_geoip_config  # noqa: E402
from graph.threat_graph import ThreatGraph  # noqa: E402
from services.app_auth import (  # noqa: E402
    is_user_authenticated,
    verify_admin_login,
    has_google_auth_config,
    get_authenticated_user_info,
    logout_user,
)

# Optional new modules (never crash the dashboard when storage is missing).
try:  # noqa: E402
    from services.header_trust import assess_origin, detect_header_anomalies
    from services.threat_intel import enrich_ip_results, ThreatIntelService, get_threat_intel_config
    from services.auth_validation import authenticate_email
    from storage.case_store import CaseStore
    from storage.compliance import ChainOfCustodyLogger
    from tracking.tracker import TrackerStore, mint_email_token, embed_html
    _HAS_NEW_MODULES = True
except Exception:  # pragma: no cover
    _HAS_NEW_MODULES = False


def save_scan_to_case_store(email_id, verdict_class, verdict_priority, combined_score, ip_risk=None, from_email="", sender_domain="", subject="", urls=None, ips=None, raw_headers=None, body_text=None):
    """Safely persist an interactive scan to CaseStore if available."""
    if _HAS_NEW_MODULES:
        try:
            store = CaseStore()
            store.store_email(
                email_id=email_id,
                verdict_class=verdict_class,
                verdict_priority=verdict_priority,
                combined_score=combined_score,
                ip_risk=ip_risk,
                from_email=from_email,
                sender_domain=sender_domain,
                subject=subject,
                urls=urls,
                ips=ips,
                raw_headers=raw_headers,
                body_text=body_text,
            )
        except Exception:
            pass


def format_ip_reputation_display(rec: dict) -> str | None:
    """Format AbuseIPDB threat intel / GeoIP reputation for UI display."""
    parts = []
    ti = rec.get("threat_intel") if isinstance(rec, dict) else None
    if ti and isinstance(ti, dict) and ti.get("ok"):
        score = ti.get("abuse_confidence_score")
        reports = ti.get("total_reports")
        ti_str = ""
        if score is not None:
            ti_str += f"{score}% confidence"
        if reports is not None:
            ti_str += f" ({reports} reports)" if ti_str else f"{reports} reports"
        if ti.get("is_tor"):
            ti_str += " [Tor]"
        if ti.get("is_proxy"):
            ti_str += " [Proxy]"
        if ti_str:
            parts.append(ti_str)

    geo = (rec.get("geo") or {}) if isinstance(rec, dict) else {}
    rep = geo.get("reputation")
    if rep and isinstance(rep, dict):
        rep_parts = []
        if rep.get("score") is not None:
            rep_parts.append(f"Score: {rep['score']}")
        rep_parts.extend(rep.get("markers") or [])
        rep_parts.extend(rep.get("flags") or [])
        if rep_parts:
            parts.append(" / ".join(rep_parts))

    return " | ".join(parts) if parts else None


# ─── Page Configuration ──────────────────────────────────────────────────────

st.set_page_config(
    page_title="🛡️ AI Phishing Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Initialize Session State ────────────────────────────────────────────────

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "total_scans" not in st.session_state:
    st.session_state.total_scans = 0
if "threats_detected" not in st.session_state:
    st.session_state.threats_detected = 0
if "safe_emails" not in st.session_state:
    st.session_state.safe_emails = 0

# ─── Custom CSS with Cyberpunk/Tech Theme ─────────────────────────────────────

st.markdown("""
<style>
    /* --- Import Google Fonts --- */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Rajdhani:wght@300;400;500;600;700&family=Share+Tech+Mono&display=swap');

    /* --- Global Styles --- */
    .stApp {
        background: radial-gradient(circle at 50% 0%, #0a0f1e 0%, #050510 100%);
        font-family: 'Rajdhani', sans-serif;
    }

    /* --- Custom Scrollbar --- */
    ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }
    ::-webkit-scrollbar-track {
        background: #050510;
        border-left: 1px solid rgba(0,255,136,0.1);
    }
    ::-webkit-scrollbar-thumb {
        background: rgba(0,255,136,0.2);
        border-radius: 5px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(0,255,136,0.5);
    }

    /* --- Animated Matrix Rain Background --- */
    .matrix-bg {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: -1;
        overflow: hidden;
        pointer-events: none;
    }
    .matrix-bg::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background:
            radial-gradient(ellipse at 20% 50%, rgba(0,255,136,0.03) 0%, transparent 50%),
            radial-gradient(ellipse at 80% 20%, rgba(0,170,255,0.04) 0%, transparent 50%),
            radial-gradient(ellipse at 50% 80%, rgba(147,51,234,0.03) 0%, transparent 50%);
        animation: ambientPulse 8s ease-in-out infinite;
    }

    @keyframes ambientPulse {
        0%, 100% { opacity: 0.5; }
        50% { opacity: 1; }
    }

    /* --- Scanlines Effect --- */
    .scanlines {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 0;
        pointer-events: none;
        background: repeating-linear-gradient(
            0deg,
            transparent,
            transparent 2px,
            rgba(0,255,136,0.008) 2px,
            rgba(0,255,136,0.008) 4px
        );
    }

    /* --- Main Title --- */
    .main-title {
        text-align: center;
        padding: 2rem 1.5rem;
        background: linear-gradient(135deg, rgba(0,255,136,0.05), rgba(0,170,255,0.05), rgba(147,51,234,0.05));
        border-radius: 20px;
        border: 1px solid rgba(0,255,136,0.15);
        margin-bottom: 2rem;
        position: relative;
        overflow: hidden;
        backdrop-filter: blur(10px);
    }
    .main-title::before {
        content: '';
        position: absolute;
        top: -2px;
        left: -2px;
        right: -2px;
        bottom: -2px;
        background: linear-gradient(45deg, #00ff88, #00aaff, #9333ea, #00ff88);
        background-size: 400% 400%;
        z-index: -1;
        border-radius: 22px;
        animation: borderGlow 6s ease infinite;
        opacity: 0.3;
    }
    @keyframes borderGlow {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    .main-title .shield-icon {
        font-size: 3.5rem;
        display: block;
        margin-bottom: 0.3rem;
        animation: shieldPulse 2s ease-in-out infinite;
    }
    @keyframes shieldPulse {
        0%, 100% { transform: scale(1); filter: drop-shadow(0 0 10px rgba(0,255,136,0.3)); }
        50% { transform: scale(1.05); filter: drop-shadow(0 0 25px rgba(0,255,136,0.6)); }
    }

    .main-title h1 {
        font-family: 'Orbitron', monospace;
        background: linear-gradient(90deg, #00ff88, #00aaff, #9333ea, #00ff88);
        background-size: 300% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.2rem;
        font-weight: 800;
        margin: 0;
        animation: gradient-shift 4s ease infinite;
        letter-spacing: 2px;
        text-transform: uppercase;
    }
    .main-title p {
        color: #64748b;
        font-size: 1.1rem;
        margin: 0.5rem 0 0 0;
        font-family: 'Share Tech Mono', monospace;
        letter-spacing: 1px;
    }
    @keyframes gradient-shift {
        0% { background-position: 0% center; }
        50% { background-position: 100% center; }
        100% { background-position: 0% center; }
    }

    /* --- Status Bar --- */
    .status-bar {
        display: flex;
        justify-content: center;
        gap: 2rem;
        padding: 0.8rem 1.5rem;
        background: rgba(0,255,136,0.03);
        border: 1px solid rgba(0,255,136,0.1);
        border-radius: 12px;
        margin-bottom: 1.5rem;
        font-family: 'Share Tech Mono', monospace;
    }
    .status-item {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.85rem;
    }
    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        animation: dotBlink 2s ease-in-out infinite;
    }
    .status-dot.green { background: #00ff88; box-shadow: 0 0 10px #00ff88; }
    .status-dot.blue { background: #00aaff; box-shadow: 0 0 10px #00aaff; }
    .status-dot.purple { background: #9333ea; box-shadow: 0 0 10px #9333ea; }

    @keyframes dotBlink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.3; }
    }

    /* --- Tech Panel / Glassmorphism Cards --- */
    .tech-panel {
        background: rgba(10, 15, 30, 0.8);
        border: 1px solid rgba(0,255,136,0.1);
        border-radius: 16px;
        padding: 1.5rem;
        margin: 0.8rem 0;
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        position: relative;
        overflow: hidden;
        transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.3s ease, border-color 0.3s ease;
    }
    .tech-panel:hover {
        transform: translateY(-4px);
        box-shadow: 0 10px 30px rgba(0,255,136,0.05);
        border-color: rgba(0,255,136,0.25);
    }
    .tech-panel::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, #00ff88, #00aaff, transparent);
        opacity: 0.5;
    }
    .tech-panel h4 {
        font-family: 'Orbitron', monospace;
        color: #00ff88;
        font-size: 0.85rem;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin: 0 0 1rem 0;
    }

    /* --- Verdict Cards --- */
    .verdict-card {
        text-align: center;
        padding: 2.5rem;
        border-radius: 20px;
        margin: 1.5rem 0;
        animation: verdictAppear 0.8s cubic-bezier(0.16, 1, 0.3, 1);
        position: relative;
        overflow: hidden;
    }
    .verdict-card::before {
        content: '';
        position: absolute;
        top: 0; left: -150%; width: 50%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
        transform: skewX(-20deg);
        animation: shimmer 4s infinite;
        pointer-events: none;
        z-index: 1;
    }
    @keyframes shimmer {
        0% { left: -150%; }
        20% { left: 200%; }
        100% { left: 200%; }
    }
    .verdict-card::after {
        content: '';
        position: absolute;
        top: 50%;
        left: 50%;
        width: 200%;
        height: 200%;
        transform: translate(-50%, -50%);
        background: radial-gradient(circle, rgba(255,255,255,0.02) 0%, transparent 60%);
        pointer-events: none;
    }
    .verdict-phishing {
        background: linear-gradient(135deg, rgba(255,50,50,0.12), rgba(255,50,50,0.03));
        border: 1px solid rgba(255,50,50,0.3);
        box-shadow: 0 0 40px rgba(255,50,50,0.08), inset 0 0 60px rgba(255,50,50,0.03);
    }
    .verdict-suspicious {
        background: linear-gradient(135deg, rgba(255,170,0,0.12), rgba(255,170,0,0.03));
        border: 1px solid rgba(255,170,0,0.3);
        box-shadow: 0 0 40px rgba(255,170,0,0.08), inset 0 0 60px rgba(255,170,0,0.03);
    }
    .verdict-safe {
        background: linear-gradient(135deg, rgba(0,255,136,0.12), rgba(0,255,136,0.03));
        border: 1px solid rgba(0,255,136,0.3);
        box-shadow: 0 0 40px rgba(0,255,136,0.08), inset 0 0 60px rgba(0,255,136,0.03);
    }
    .verdict-emoji {
        font-size: 4.5rem;
        margin-bottom: 0.5rem;
        animation: emojiPulse 1.5s ease-in-out infinite;
    }
    @keyframes emojiPulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.1); }
    }
    .verdict-text {
        font-family: 'Orbitron', monospace;
        font-size: 1.6rem;
        font-weight: 700;
        margin: 0.5rem 0;
        letter-spacing: 2px;
        text-transform: uppercase;
    }
    .verdict-score {
        font-family: 'Share Tech Mono', monospace;
        font-size: 1.1rem;
        color: #64748b;
    }

    @keyframes verdictAppear {
        from { opacity: 0; transform: scale(0.9) translateY(30px); }
        to { opacity: 1; transform: scale(1) translateY(0); }
    }

    /* --- Metric Boxes --- */
    .metric-box {
        background: rgba(10, 15, 30, 0.8);
        border: 1px solid rgba(0,255,136,0.12);
        border-radius: 16px;
        padding: 1.2rem;
        text-align: center;
        margin: 0.3rem 0;
        position: relative;
        overflow: hidden;
        backdrop-filter: blur(10px);
    }
    .metric-box::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, #00aaff, transparent);
    }
    .metric-value {
        font-family: 'Orbitron', monospace;
        font-size: 2rem;
        font-weight: 700;
        color: #00ff88;
        text-shadow: 0 0 20px rgba(0,255,136,0.3);
    }
    .metric-label {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.8rem;
        color: #64748b;
        margin-top: 0.3rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* --- Score Bar --- */
    .score-bar-container {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 12px;
        height: 24px;
        overflow: hidden;
        margin: 0.5rem 0;
        position: relative;
    }
    .score-bar {
        height: 100%;
        border-radius: 12px;
        transition: width 1.5s cubic-bezier(0.16, 1, 0.3, 1);
        position: relative;
        overflow: hidden;
    }
    .score-bar::after {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
        animation: barShine 2s ease-in-out infinite;
    }
    @keyframes barShine {
        0% { left: -100%; }
        100% { left: 100%; }
    }

    /* --- Finding Items --- */
    .finding-item {
        background: rgba(0,255,136,0.03);
        border-left: 3px solid rgba(0,255,136,0.4);
        padding: 0.7rem 1rem;
        margin: 0.5rem 0;
        border-radius: 0 10px 10px 0;
        font-size: 0.95rem;
        font-family: 'Rajdhani', sans-serif;
        color: #c8d6e5;
        transition: all 0.3s ease;
    }
    .finding-item:hover {
        background: rgba(0,255,136,0.06);
        border-left-color: #00ff88;
        transform: translateX(4px);
    }

    /* --- Info Cards --- */
    .info-card {
        background: rgba(10, 15, 30, 0.6);
        border: 1px solid rgba(0,255,136,0.08);
        border-radius: 14px;
        padding: 1.2rem;
        margin: 0.5rem 0;
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .info-card:hover {
        transform: translateY(-3px);
        border-color: rgba(0,255,136,0.3);
        box-shadow: 0 8px 25px rgba(0,255,136,0.1);
    }
    .info-card h4 {
        font-family: 'Orbitron', monospace;
        color: #00ff88;
        margin: 0 0 0.5rem 0;
        font-size: 0.8rem;
        letter-spacing: 1px;
        text-transform: uppercase;
    }

    /* --- Sidebar --- */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #050510 0%, #0a0a1a 50%, #0f0f23 100%);
        border-right: 1px solid rgba(0,255,136,0.1);
    }

    /* --- Threat Radar --- */
    .threat-radar {
        width: 200px;
        height: 200px;
        border-radius: 50%;
        border: 2px solid rgba(0,255,136,0.2);
        margin: 1rem auto;
        position: relative;
        background: radial-gradient(circle, rgba(0,255,136,0.02) 0%, transparent 70%);
    }
    .radar-sweep {
        position: absolute;
        top: 50%;
        left: 50%;
        width: 50%;
        height: 2px;
        transform-origin: left center;
        background: linear-gradient(90deg, rgba(0,255,136,0.6), transparent);
        animation: radarSweep 3s linear infinite;
    }
    .radar-ring {
        position: absolute;
        border-radius: 50%;
        border: 1px solid rgba(0,255,136,0.1);
    }
    .radar-ring-1 { top: 25%; left: 25%; width: 50%; height: 50%; }
    .radar-ring-2 { top: 10%; left: 10%; width: 80%; height: 80%; }
    .radar-crosshair-h {
        position: absolute;
        top: 50%;
        left: 0;
        width: 100%;
        height: 1px;
        background: rgba(0,255,136,0.08);
    }
    .radar-crosshair-v {
        position: absolute;
        left: 50%;
        top: 0;
        width: 1px;
        height: 100%;
        background: rgba(0,255,136,0.08);
    }

    @keyframes radarSweep {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }

    /* --- Stats Dashboard --- */
    .stat-card {
        background: rgba(10, 15, 30, 0.9);
        border: 1px solid rgba(0,255,136,0.1);
        border-radius: 12px;
        padding: 1rem;
        text-align: center;
        margin: 0.4rem 0;
    }
    .stat-value {
        font-family: 'Orbitron', monospace;
        font-size: 1.6rem;
        font-weight: 700;
    }
    .stat-label {
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.7rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* --- History Table --- */
    .history-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.6rem 0.8rem;
        border-bottom: 1px solid rgba(255,255,255,0.04);
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.8rem;
        color: #94a3b8;
    }
    .history-item:hover {
        background: rgba(0,255,136,0.03);
    }

    /* --- Cyber Grid Decoration --- */
    .cyber-grid {
        position: relative;
        padding: 1rem;
    }
    .cyber-grid::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-image:
            linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px);
        background-size: 30px 30px;
        pointer-events: none;
        border-radius: 16px;
    }

    /* --- Section Divider --- */
    .section-divider {
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(0,255,136,0.3), rgba(0,170,255,0.3), transparent);
        margin: 2rem 0;
    }

    /* --- Terminal Text --- */
    .terminal-text {
        font-family: 'Share Tech Mono', monospace;
        color: #00ff88;
        font-size: 0.9rem;
    }

    /* --- Animated Scanning Text --- */
    .scanning-text {
        font-family: 'Share Tech Mono', monospace;
        color: #00ff88;
        text-align: center;
        animation: scanBlink 0.5s ease-in-out infinite;
    }
    @keyframes scanBlink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }

    /* --- Tips/Help Section Styling --- */
    .tip-card {
        background: linear-gradient(135deg, rgba(0,170,255,0.06), rgba(147,51,234,0.06));
        border: 1px solid rgba(0,170,255,0.15);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin: 0.5rem 0;
        font-size: 0.9rem;
        color: #c8d6e5;
    }
    .tip-card .tip-title {
        font-family: 'Orbitron', monospace;
        color: #00aaff;
        font-size: 0.75rem;
        letter-spacing: 1px;
        margin-bottom: 0.5rem;
        text-transform: uppercase;
    }

    /* --- Odometer / Gauge --- */
    .gauge-container {
        position: relative;
        width: 260px;
        height: 150px;
        margin: 0 auto;
    }
    .gauge-bg {
        position: absolute;
        top: 0;
        left: 0;
        width: 260px;
        height: 130px;
        border-radius: 130px 130px 0 0;
        background: conic-gradient(
            from 0.75turn,
            #00ff88 0deg,
            #44dd66 36deg,
            #FFD700 72deg,
            #FFA500 108deg,
            #FF6B35 144deg,
            #FF4444 180deg
        );
        overflow: hidden;
    }
    .gauge-bg::after {
        content: '';
        position: absolute;
        bottom: 0;
        left: 50%;
        transform: translateX(-50%);
        width: 200px;
        height: 100px;
        border-radius: 100px 100px 0 0;
        background: #0a0f1e;
    }
    .gauge-needle {
        position: absolute;
        bottom: 0;
        left: 50%;
        width: 4px;
        height: 110px;
        background: linear-gradient(to top, #fff 0%, #fff 60%, transparent 100%);
        transform-origin: bottom center;
        border-radius: 4px;
        z-index: 10;
        transition: transform 1.5s cubic-bezier(0.34, 1.56, 0.64, 1);
        filter: drop-shadow(0 0 6px rgba(255,255,255,0.4));
    }
    .gauge-needle::after {
        content: '';
        position: absolute;
        bottom: -6px;
        left: 50%;
        transform: translateX(-50%);
        width: 14px;
        height: 14px;
        border-radius: 50%;
        background: #fff;
        box-shadow: 0 0 10px rgba(255,255,255,0.5);
    }
    .gauge-labels {
        position: absolute;
        bottom: 2px;
        left: 0;
        width: 100%;
        display: flex;
        justify-content: space-between;
        padding: 0 10px;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.65rem;
        color: #64748b;
    }
    .gauge-value {
        text-align: center;
        font-family: 'Orbitron', monospace;
        font-size: 2rem;
        font-weight: 700;
        margin-top: -5px;
    }
    .gauge-label-text {
        text-align: center;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.8rem;
        color: #64748b;
        letter-spacing: 2px;
        text-transform: uppercase;
    }

    /* --- Streamlit Buttons Overrides --- */
    .stButton > button {
        background: rgba(10, 15, 30, 0.7) !important;
        border: 1px solid rgba(0,255,136,0.3) !important;
        color: #00ff88 !important;
        border-radius: 8px !important;
        font-family: 'Share Tech Mono', monospace !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 0 10px rgba(0,255,136,0.0) !important;
    }
    .stButton > button:hover {
        background: rgba(0,255,136,0.1) !important;
        border-color: #00ff88 !important;
        color: #fff !important;
        box-shadow: 0 0 15px rgba(0,255,136,0.3) !important;
        transform: translateY(-2px) !important;
    }
    .stButton > button[kind="primary"] {
        background: linear-gradient(90deg, rgba(0,255,136,0.2), rgba(0,170,255,0.2)) !important;
        border: 1px solid #00aaff !important;
        color: #fff !important;
        text-shadow: 0 0 5px rgba(255,255,255,0.5) !important;
    }
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(90deg, rgba(0,255,136,0.4), rgba(0,170,255,0.4)) !important;
        box-shadow: 0 0 20px rgba(0,170,255,0.4) !important;
    }

    /* --- Streamlit Tabs Styling --- */
    [data-testid="stTabs"] {
        background: rgba(10, 15, 30, 0.6);
        border-radius: 12px;
        padding: 0.5rem;
        border: 1px solid rgba(0,255,136,0.1);
        margin-bottom: 1rem;
    }
    [data-testid="stTabs"] button[role="tab"] {
        background: transparent !important;
        border: none !important;
        color: #64748b !important;
        font-family: 'Orbitron', monospace !important;
        font-size: 0.9rem !important;
        letter-spacing: 1px !important;
        text-transform: uppercase !important;
        padding: 0.8rem 1.5rem !important;
        border-radius: 8px !important;
        transition: all 0.3s ease !important;
        margin-right: 0.5rem !important;
    }
    [data-testid="stTabs"] button[role="tab"]:hover {
        color: #00ff88 !important;
        background: rgba(0,255,136,0.05) !important;
    }
    [data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
        color: #00ff88 !important;
        background: rgba(0,255,136,0.1) !important;
        box-shadow: inset 0 -2px 0 #00ff88, 0 4px 10px rgba(0,255,136,0.1) !important;
    }
    [data-testid="stTabs"] button[role="tab"]:focus {
        outline: none !important;
        box-shadow: none !important;
    }

    /* --- Streamlit Text Area Overrides --- */
    .stTextArea > div > div > textarea {
        background: rgba(5, 5, 16, 0.8) !important;
        border: 1px solid rgba(0,255,136,0.2) !important;
        color: #c8d6e5 !important;
        font-family: 'Rajdhani', sans-serif !important;
        font-size: 1.05rem !important;
        border-radius: 10px !important;
        transition: all 0.3s ease !important;
    }
    .stTextArea > div > div > textarea:focus {
        border-color: #00ff88 !important;
        box-shadow: 0 0 15px rgba(0,255,136,0.15) !important;
        background: rgba(10, 15, 30, 0.9) !important;
    }

    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* Style text area */
    .stTextArea textarea {
        background: rgba(10, 15, 30, 0.8) !important;
        border: 1px solid rgba(0,255,136,0.15) !important;
        border-radius: 12px !important;
        color: #e2e8f0 !important;
        font-family: 'Rajdhani', sans-serif !important;
        font-size: 1rem !important;
    }
    .stTextArea textarea:focus {
        border-color: rgba(0,255,136,0.4) !important;
        box-shadow: 0 0 20px rgba(0,255,136,0.08) !important;
    }

    /* Style buttons */
    .stButton > button {
        font-family: 'Orbitron', monospace !important;
        letter-spacing: 1px !important;
        text-transform: uppercase !important;
        font-size: 0.8rem !important;
        border-radius: 10px !important;
        transition: all 0.3s ease !important;
    }
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #00ff88, #00aaff) !important;
        color: #050510 !important;
        border: none !important;
        font-weight: 700 !important;
    }
    .stButton > button[kind="primary"]:hover {
        box-shadow: 0 0 30px rgba(0,255,136,0.3) !important;
        transform: translateY(-2px) !important;
    }
    .stButton > button[kind="secondary"] {
        background: rgba(0,255,136,0.05) !important;
        border: 1px solid rgba(0,255,136,0.2) !important;
        color: #00ff88 !important;
    }
    .stButton > button[kind="secondary"]:hover {
        background: rgba(0,255,136,0.1) !important;
        border-color: rgba(0,255,136,0.4) !important;
    }

    /* Style file uploader */
    [data-testid="stFileUploader"] {
        background: rgba(10, 15, 30, 0.6);
        border: 1px dashed rgba(0,255,136,0.15);
        border-radius: 12px;
        padding: 0.5rem;
    }

    /* Style expander */
    .streamlit-expanderHeader {
        font-family: 'Share Tech Mono', monospace !important;
        color: #00ff88 !important;
    }

</style>
""", unsafe_allow_html=True)


# ─── Background Effects ──────────────────────────────────────────────────────

st.markdown("""
<div class="matrix-bg"></div>
<div class="scanlines"></div>
""", unsafe_allow_html=True)


def render_cyberforge_login_page():
    st.markdown("""
    <div class="main-title">
        <span class="shield-icon">🛡️</span>
        <h1>CyberForge AI Phishing Shield</h1>
        <p>AUTHENTICATION REQUIRED · SECURE SYSTEM ACCESS</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="status-bar">
        <div class="status-item"><span class="status-dot green"></span> SECURE OIDC PROTOCOL</div>
        <div class="status-item"><span class="status-dot blue"></span> PBKDF2 ADMIN FALLBACK</div>
        <div class="status-item"><span class="status-dot purple"></span> ZERO TRUST ACCESS</div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div class="tech-panel">
            <h4>🔐 SYSTEM AUTHENTICATION</h4>
        </div>
        """, unsafe_allow_html=True)

        login_tab1, login_tab2 = st.tabs(["🌐 GOOGLE OIDC", "🔑 LOCAL ADMIN"])

        with login_tab1:
            st.markdown("<p style='color:#c8d6e5; font-size:0.95rem;'>Authenticate using your Google Workspace / Google Account.</p>", unsafe_allow_html=True)
            if has_google_auth_config():
                if st.button("CONTINUE WITH GOOGLE", key="btn_google_login", type="primary", use_container_width=True):
                    st.login()
            else:
                st.markdown("""
                <div class="tip-card" style="border-color: rgba(0,170,255,0.3);">
                    <div class="tip-title">ℹ️ GOOGLE OIDC UNCONFIGURED</div>
                    Google authentication configuration is not yet set in <code>.streamlit/secrets.toml</code>.<br>
                    Please use <strong>Local Admin Login</strong> below to access CyberForge.
                </div>
                """, unsafe_allow_html=True)
                st.button("CONTINUE WITH GOOGLE (UNCONFIGURED)", key="btn_google_disabled", disabled=True, use_container_width=True)

        with login_tab2:
            st.markdown("<p style='color:#c8d6e5; font-size:0.95rem;'>Enter administrator credentials for direct system access.</p>", unsafe_allow_html=True)
            with st.form("local_admin_login_form"):
                admin_user_input = st.text_input("ADMIN USERNAME", key="admin_user_input", placeholder="enter admin username")
                admin_pass_input = st.text_input("PASSWORD", type="password", key="admin_pass_input", placeholder="enter admin password")
                submit_admin = st.form_submit_button("AUTHENTICATE AS ADMIN", type="primary", use_container_width=True)

                if submit_admin:
                    if verify_admin_login(admin_user_input, admin_pass_input):
                        st.session_state["authenticated_admin"] = True
                        st.session_state["admin_user"] = admin_user_input.strip() or "admin"
                        st.success("AUTHENTICATION SUCCESSFUL — INITIALIZING DASHBOARD...")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error("INVALID CREDENTIALS — ACCESS DENIED")


if not is_user_authenticated():
    render_cyberforge_login_page()
    st.stop()


# ─── Load Model ──────────────────────────────────────────────────────────────

@st.cache_resource
def get_model():
    """Load the trained model (cached)."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "model.pkl")
    vectorizer_path = os.path.join(script_dir, "vectorizer.pkl")
    return load_model(model_path, vectorizer_path)


model, vectorizer = get_model()
model_loaded = model is not None and vectorizer is not None


# ─── Sample Emails ───────────────────────────────────────────────────────────

SAMPLE_PHISHING = """Dear Customer,

We have detected unusual activity on your bank account. Your account has been temporarily suspended for security reasons.

URGENT: You must verify your identity within 24 hours or your account will be permanently closed.

Click here to verify your account: http://secure-banking-verify.tk/login

Please provide your:
- Full Name
- Account Number
- Social Security Number
- Password

Failure to act immediately will result in permanent account closure and loss of funds.

Security Team
First National Bank"""

SAMPLE_SAFE = """Hi Team,

Just a quick reminder that our weekly standup meeting has been moved to Thursday at 10:00 AM this week due to the holiday on Wednesday.

Please make sure to prepare your updates:
- What you worked on last week
- What you plan to work on this week
- Any blockers or concerns

The meeting will be in Conference Room B. Remote team members can join via the usual Zoom link.

Thanks,
Sarah Johnson
Project Manager"""

SAMPLE_SUSPICIOUS = """Hello,

Your subscription to CloudStorage Plus is about to expire. Your files may be at risk.

Renew your subscription now to avoid losing your data. Special offer: 50% off for the next 24 hours only!

Visit our website to renew: www.cloudstorage-plus-renew.com/special-offer

Thank you,
CloudStorage Plus Team"""

SAMPLE_SPEAR = """Dear John,

I'm reaching out from the IT Department regarding the recent security update. As discussed in last week's all-hands meeting, we need all employees to reset their credentials by EOD today.

Your employee ID (EMP-48291) has been flagged for immediate update. Please use the secure portal below:

http://company-internal-portal.xyz/reset?id=48291

This is mandatory per the new compliance policy (ref: SEC-2024-0092). If you have questions, contact the help desk.

Best regards,
Mike Thompson
Senior IT Administrator"""

# Header-rich samples for the Email Header Forensics mode. These carry real
# envelope fields (From/To/Cc/Bcc/Sender/Return-Path/Envelope-To/Received) so
# the header analysis has something to evaluate - unlike the body-only samples.
SAMPLE_FORENSIC_PHISHING = """Return-Path: <bounce-3@secure-banking-verify.tk>
From: "First National Bank Security" <security@secure-banking-verify.tk>
To: victim@corp.example
Bcc: corpusgrp@groups.example
Subject: URGENT: Your account has been suspended
Reply-To: "Account Support" <support@secure-banking-verify.tk>
Date: Sat, 05 Sep 2026 21:41:00 +0000
Message-ID: <1441b.abcdef@secure-banking-verify.tk>
Envelope-To: helpdesk@corp.example
X-Originating-IP: [203.0.113.47]
DKIM-Signature: v=1; a=rsa-sha256; d=secure-banking-verify.tk; s=sel; b=fake
Authentication-Results: mx.corp.example; spf=fail smtp.mailfrom=secure-banking-verify.tk; dkim=fail header.d=secure-banking-verify.tk; dmarc=fail
Received: from mx1.corp.example (unknown [198.51.100.8]) by exchange.corp.example; Sat, 05 Sep 2026 21:42:10 +0000
Received: from secure-banking-verify.tk (unknown [203.0.113.47]) by mx1.corp.example; Sat, 05 Sep 2026 21:41:11 +0000

Dear Customer,

We have detected unusual activity on your bank account. Your account has been temporarily suspended for security reasons.

URGENT: You must verify your identity within 24 hours or your account will be permanently closed.

Click here to verify your account: http://secure-banking-verify.tk/login

Security Team
First National Bank"""

SAMPLE_FORENSIC_SAFE = """Return-Path: <sarah.johnson@example.com>
From: Sarah Johnson <sarah.johnson@example.com>
To: project-team@example.com
Subject: Weekly standup moved to Thursday
Date: Tue, 01 Sep 2026 08:00:00 -0400
Message-ID: <CABabc123@mail.example.com>
Reply-To: sarah.johnson@example.com
Envelope-To: project-team@example.com
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=google; b=abc
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass
Received: from mail.example.com (mail.example.com [203.0.113.21]) by mx.example.com; Tue, 01 Sep 2026 08:00:05 -0400

Hi Team,

Just a quick reminder that our weekly standup meeting has been moved to Thursday at 10:00 AM this week.

Thanks,
Sarah"""

SAMPLE_FORENSIC_SPEAR = """Return-Path: <sys@corp-verify-it.xyz>
From: "IT Support" <sys@corp-verify-it.xyz>
To: john.doe@corp.example
Cc: john.doe.emails@gmail.com
Subject: Mandatory credential reset (SEC-2024-0092)
Reply-To: <sys@corp-verify-it.xyz>
Date: Thu, 03 Sep 2026 14:12:00 +0000
Message-ID: <9f.9021@corp-verify-it.xyz>
Delivered-To: john.doe@corp.example
Envelope-To: helpdesk@corp.example
X-Originating-IP: [198.51.100.63]
Authentication-Results: mx.corp.example; spf=fail smtp.mailfrom=corp-verify-it.xyz; dkim=neutral header.d=corp-verify-it.xyz; dmarc=none
Received: from corp-verify-it.xyz (unknown [198.51.100.63]) by mx.corp.example; Thu, 03 Sep 2026 14:12:30 +0000

Hi John,

From the IT Department regarding the recent security update: we need you to reset your credentials by EOD today.

Use the secure portal: http://company-internal-portal.xyz/reset?id=48291

Mike"""

# ─── Sample URLs ─────────────────────────────────────────────────────────────

SAMPLE_URL_PHISHING = "http://192.168.1.1/secure-banking-login/verify-account.php"
SAMPLE_URL_SUSPICIOUS = "http://amaz0n-account-verify.tk/update?user=12345"
SAMPLE_URL_SAFE = "https://www.google.com/search?q=weather"

# ─── Sample Social Engineering Messages ──────────────────────────────────────

SE_SAMPLE_PHISHING = """Dear Customer,

We noticed unusual activity on your account. Your account has been temporarily suspended.

URGENT: You must verify your account within 24 hours or your account will be closed permanently.

Click here to verify your account: http://secure-banking-verify.tk/login

Please confirm your details including your Social Security Number and password.

Failure to act immediately will result in permanent account closure.

Security Alert Team"""

SE_SAMPLE_SPEAR = """Hi John,

Following up on our conversation last week — as discussed with your manager, your department needs to complete the mandatory security update. Your employee ID (EMP-48291) has been flagged.

As per your request, I've set up the secure portal for your team:
http://company-internal-portal.xyz/reset?id=48291

Your colleague Sarah already completed this. Please handle this immediately as it's a regulatory requirement per the new compliance policy.

Best regards,
Mike Thompson
Senior IT Administrator"""

SE_SAMPLE_PRETEXTING = """Hello,

This is from the IT Department. We are conducting a routine security audit as part of our company policy. All employees are required to complete a mandatory update.

As the compliance officer, I need to verify your access credentials for the new verification process. This is a regulatory requirement for the background check.

Please provide your current login and password so we can complete the security review. The help desk will process your access review by end of day.

Thank you for your cooperation.
IT Support Team"""

SE_SAMPLE_BAITING = """🎉 CONGRATULATIONS! 🎉

You have won a $1,000 Amazon Gift Card! You've been specially selected as a lucky winner in our annual sweepstakes!

Claim your prize now — this exclusive deal is available for a limited time only!

Free gift card waiting: http://free-amazon-prize.tk/claim

As a bonus offer, you'll also receive a free iPhone and free vacation package!

No cost to you — completely free! Don't miss this reward!"""

SE_SAMPLE_CEO_FRAUD = """From the desk of the CEO:

I need you to handle this immediately. I'm in a meeting and cannot call right now.

Please process an urgent wire transfer of $45,000 to the following account. This is a confidential matter — do not discuss this with anyone else. Keep this between us.

I need you to authorize payment and process this today. This is a direct order, board approved.

I'm traveling tomorrow so this must be done before EOD.

- James Morrison, CEO"""

SE_SAMPLE_TECH_SUPPORT = """⚠️ MICROSOFT ALERT ⚠️

Virus detected on your computer! Your system is compromised and a security breach has been detected.

DO NOT TURN OFF your computer. DO NOT RESTART.

Your IP has been flagged and your firewall alert is critical. Malware found in system files.

Call Microsoft Tech Support immediately: 1-800-FAKE-NUM

Our team will need remote access via TeamViewer to fix your computer. License expired — activation required.

Call immediately to prevent data loss!"""

SE_SAMPLE_ROMANCE = """My Dear,

I've fallen in love with you since we started talking. You are my soul mate — destiny brought us together. My darling, I think about you every day.

I need money for a medical emergency. I'm stuck at the hospital and the bills are piling up. Can you send $2,000 via Western Union? I promise to repay everything when I travel to meet you.

There's also an inheritance money opportunity I want to share with you. Please help me financially just this once.

I love you with all my heart."""

SE_SAMPLE_INVOICE = """URGENT: Invoice Attached — Payment Due Immediately

Dear Accounts Payable,

Please note our updated banking details for all future vendor payments. Our bank details have changed effective immediately.

Outstanding balance: $28,750.00
Payment required by: Today
Overdue payment reference: INV-2024-8891

Please process payment via ACH transfer to our new bank account. Wire instructions attached.

This is from the billing department. Please pay immediately to avoid service interruption.

Revised invoice attached with updated payment information.

Regards,
Accounts Department"""

SE_SAMPLE_SAFE = """Hi Team,

Just a reminder that our quarterly planning meeting is scheduled for next Tuesday at 2 PM in Conference Room A.

Please prepare a brief update on your current projects and any resource needs for Q3.

The agenda has been shared via the calendar invite. Let me know if you have any questions.

Best,
Sarah"""

SE_SAMPLES = {
    "phishing": ("🎣 Phishing", SE_SAMPLE_PHISHING),
    "spear": ("🎯 Spear Phish", SE_SAMPLE_SPEAR),
    "pretexting": ("🎭 Pretexting", SE_SAMPLE_PRETEXTING),
    "baiting": ("🪤 Baiting", SE_SAMPLE_BAITING),
    "ceo": ("👔 CEO Fraud", SE_SAMPLE_CEO_FRAUD),
    "tech": ("🖥️ Tech Scam", SE_SAMPLE_TECH_SUPPORT),
    "romance": ("💕 Romance Scam", SE_SAMPLE_ROMANCE),
    "invoice": ("📦 Invoice Fraud", SE_SAMPLE_INVOICE),
    "safe": ("✅ Safe Message", SE_SAMPLE_SAFE),
}

# ─── IP Intelligence sample (full headers: docs, private, IPv6, duplicates) ──

SAMPLE_IP_INTEL = """From: "Security Alert" <security@secure-banking-verify.tk>
To: victim@example.com
Subject: URGENT: Verify your account
Date: Sat, 05 Sep 2026 10:15:03 +0000
Message-ID: <20260905.101503.abc123@secure-banking-verify.tk>
Reply-To: security-noreply@secure-banking-verify.tk
X-Originating-IP: [203.0.113.45]
X-Sender-IP: 203.0.113.45
MIME-Version: 1.0
Received: from mail2.lab.internal (mail2.lab.internal [2001:db8:85a3::8a2e:370:7334])
	by smtp.internal-relay with SMTP id QWER0001;
	Sat, 05 Sep 2026 10:14:58 +0000
Received: from smtp.internal-relay (smtp.internal-relay [10.0.0.25])
	by mail.secure-banking-verify.tk with SMTP id XYZ789
	for <victim@example.com>; Sat, 05 Sep 2026 10:14:55 +0000
Received: from mail.secure-banking-verify.tk (mail.secure-banking-verify.tk [203.0.113.45])
	by mx.example.com with ESMTP id ABC123
	for <victim@example.com>; Sat, 05 Sep 2026 10:15:03 +0000

Dear Customer,

We detected unusual activity on your account. Your account has been temporarily
suspended for security reasons. You must verify your identity within 24 hours.

Click here to verify your account: http://secure-banking-verify.tk/login

Security Team
First National Bank"""


# ─── Sidebar ─────────────────────────────────────────────────────────────────

with st.sidebar:
    # User Profile & Logout
    user_info = get_authenticated_user_info()
    st.markdown(f"""
    <div class="tech-panel" style="padding: 0.8rem 1rem; margin-bottom: 0.8rem;">
        <h4 style="margin: 0 0 0.4rem 0;">👤 AUTHENTICATED SESSION</h4>
        <div style="font-family:'Share Tech Mono', monospace; font-size:0.85rem; color:#00ff88;">
            {user_info['name']}
        </div>
        <div style="font-family:'Share Tech Mono', monospace; font-size:0.75rem; color:#64748b;">
            {user_info['email']}
        </div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("🚪 LOG OUT", key="sidebar_logout_btn", use_container_width=True):
        logout_user()

    st.markdown("---")

    # Animated Radar
    st.markdown("""
    <div style="text-align:center; margin-bottom: 1rem;">
        <div class="threat-radar">
            <div class="radar-ring radar-ring-1"></div>
            <div class="radar-ring radar-ring-2"></div>
            <div class="radar-crosshair-h"></div>
            <div class="radar-crosshair-v"></div>
            <div class="radar-sweep"></div>
        </div>
        <div class="terminal-text" style="font-size: 0.75rem; margin-top: 0.5rem;">
            ⬤ THREAT RADAR ACTIVE
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # Session Stats
    st.markdown("""
    <div class="tech-panel">
        <h4>📊 Session Stats</h4>
    </div>
    """, unsafe_allow_html=True)

    stat_cols = st.columns(3)
    with stat_cols[0]:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value" style="color: #00aaff;">{st.session_state.total_scans}</div>
            <div class="stat-label">Scanned</div>
        </div>
        """, unsafe_allow_html=True)
    with stat_cols[1]:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value" style="color: #FF4444;">{st.session_state.threats_detected}</div>
            <div class="stat-label">Threats</div>
        </div>
        """, unsafe_allow_html=True)
    with stat_cols[2]:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value" style="color: #00ff88;">{st.session_state.safe_emails}</div>
            <div class="stat-label">Safe</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # How It Works
    st.markdown("""
    <div class="tech-panel">
        <h4>⚙️ System Modules</h4>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("📋 Rule Engine", expanded=False):
        st.markdown("""
        Scans for known phishing indicators:
        - 🔑 Phishing keywords & phrases
        - 🔗 Suspicious URLs & domains
        - ⚡ Urgency language patterns
        - 🔠 Excessive CAPS usage
        - 💰 Financial references
        """)

    with st.expander("🤖 ML Neural Core", expanded=False):
        st.markdown("""
        Trained machine learning model:
        - **TF-IDF** text vectorization
        - **Naive Bayes** / **Logistic Regression**
        - Trained on labeled email dataset
        - Provides confidence scores
        """)

    with st.expander("🔄 Fusion Algorithm", expanded=False):
        st.markdown("""
        Results are weighted and combined:
        - Rule Engine: **40%** weight
        - ML Neural Core: **60%** weight
        - **≥60**: 🚨 Phishing
        - **35-59**: ⚠️ Suspicious
        - **<35**: ✅ Safe
        """)

    st.markdown("---")

    # Model Status
    if model_loaded:
        st.markdown("""
        <div style="text-align:center; padding: 0.5rem; background: rgba(0,255,136,0.05); border: 1px solid rgba(0,255,136,0.2); border-radius: 10px;">
            <span class="terminal-text">✅ ML CORE: ONLINE</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="text-align:center; padding: 0.5rem; background: rgba(255,165,0,0.05); border: 1px solid rgba(255,165,0,0.2); border-radius: 10px;">
            <span class="terminal-text" style="color: #FFA500;">⚠️ ML CORE: OFFLINE</span>
        </div>
        """, unsafe_allow_html=True)
        st.caption("Run `python train_model.py` to activate ML.")

    st.markdown("---")

    # Scan History
    if st.session_state.scan_history:
        st.markdown("""
        <div class="tech-panel">
            <h4>📜 Scan History</h4>
        </div>
        """, unsafe_allow_html=True)
        for entry in reversed(st.session_state.scan_history[-5:]):
            emoji_map = {"phishing": "🚨", "suspicious": "⚠️", "safe": "✅"}
            color_map = {"phishing": "#FF4444", "suspicious": "#FFA500", "safe": "#00ff88"}
            e = emoji_map.get(entry["verdict"], "❓")
            c = color_map.get(entry["verdict"], "#fff")
            preview = entry["preview"][:30] + "..." if len(entry["preview"]) > 30 else entry["preview"]
            st.markdown(f"""
            <div class="history-item">
                <span>{e} {preview}</span>
                <span style="color:{c}; font-weight:600;">{entry['score']}%</span>
            </div>
            """, unsafe_allow_html=True)

    if st.session_state.get("current_investigation"):
        inv = st.session_state["current_investigation"]
        report_json = json.dumps(inv, indent=2, default=str)
        st.download_button(
            label="📥 EXPORT REPORT (JSON)",
            data=report_json,
            file_name=f"investigation_{inv.get('scan_id', 'report')}.json",
            mime="application/json",
            use_container_width=True,
            key="export_investigation_json",
        )

    st.markdown("---")
    st.markdown(
        "<div style='text-align:center; font-family: Share Tech Mono; color:#384050; font-size:0.7rem;'>"
        "AI PHISHING SHIELD v2.0<br>"
        "[ SYSTEM OPERATIONAL ]"
        "</div>",
        unsafe_allow_html=True,
    )


# ─── Main Content ────────────────────────────────────────────────────────────

# Title
st.markdown("""
<div class="main-title">
    <span class="shield-icon">🛡️</span>
    <h1>AI Phishing Shield</h1>
    <p>[ INTELLIGENT EMAIL &amp; URL THREAT DETECTION SYSTEM ]</p>
</div>
""", unsafe_allow_html=True)

# Status Bar
current_time = datetime.now().strftime("%H:%M:%S")
st.markdown(f"""
<div class="status-bar">
    <div class="status-item">
        <div class="status-dot green"></div>
        <span style="color:#00ff88;">SYSTEM ACTIVE</span>
    </div>
    <div class="status-item">
        <div class="status-dot blue"></div>
        <span style="color:#00aaff;">RULES ENGINE: LOADED</span>
    </div>
    <div class="status-item">
        <div class="status-dot {'green' if model_loaded else 'purple'}"></div>
        <span style="color:{'#00ff88' if model_loaded else '#FFA500'};">ML CORE: {'ONLINE' if model_loaded else 'OFFLINE'}</span>
    </div>
    <div class="status-item">
        <span style="color:#64748b;">🕐 {current_time}</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ─── Tabs ────────────────────────────────────────────────────────────────────

email_tab, url_tab, se_tab, forensics_tab, ip_intel_tab, cases_tab, auth_tab = st.tabs(["📧 Email Analysis", "🔗 URL Analysis", "🕵️ Social Engineering", "🔬 GeoLocation & Forensics", "🛰️ IP Intelligence & Geolocation", "🕸️ Origin & Cases", "🔑 Auth & Tracking"])

with email_tab:
    # Sample email buttons
    st.markdown("""
    <div class="tech-panel">
        <h4>📧 Quick Threat Samples</h4>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button("🚨 Phishing", use_container_width=True, type="secondary"):
            st.session_state["email_input"] = SAMPLE_PHISHING
    with col2:
        if st.button("⚠️ Suspicious", use_container_width=True, type="secondary"):
            st.session_state["email_input"] = SAMPLE_SUSPICIOUS
    with col3:
        if st.button("✅ Safe Email", use_container_width=True, type="secondary"):
            st.session_state["email_input"] = SAMPLE_SAFE
    with col4:
        if st.button("🎯 Spear Phish", use_container_width=True, type="secondary"):
            st.session_state["email_input"] = SAMPLE_SPEAR

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # Input section
    st.markdown("""
    <div class="tech-panel">
        <h4>✍️ Email Input Terminal</h4>
    </div>
    """, unsafe_allow_html=True)

    email_text = st.text_area(
        "Enter or paste the email you want to analyze:",
        value=st.session_state.get("email_input", ""),
        height=220,
        placeholder=">> Paste email content here for threat analysis...",
        label_visibility="collapsed",
    )

    # File upload
    uploaded_file = st.file_uploader(
        "Or upload an email file",
        type=["txt", "eml"],
        help="Upload a .txt or .eml file containing the email",
    )

    raw_eml_bytes = None
    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        raw_text = file_bytes.decode("utf-8", errors="ignore")
        if uploaded_file.name.lower().endswith(".eml"):
            parsed_eml = parse_eml_file(file_bytes)
            raw_eml_bytes = file_bytes
            email_text = parsed_eml["body_text"] if parsed_eml["body_text"].strip() else raw_text
            st.info(f"📄 .EML File loaded & parsed: **{uploaded_file.name}** (From: `{parsed_eml['from_email'] or 'N/A'}`, Subject: `{parsed_eml['subject'] or 'N/A'}`)")
        else:
            parsed_eml = parse_eml_file(raw_text)
            email_text = raw_text
            st.info(f"📄 File loaded: **{uploaded_file.name}** ({len(email_text)} characters)")

        st.session_state["raw_eml_bytes"] = file_bytes
        st.session_state["raw_eml_text"] = raw_text
        st.session_state["parsed_eml"] = parsed_eml
        st.session_state["forensic_email"] = raw_text
        st.session_state["forensic_email_textarea"] = raw_text
        st.session_state["full_forensic_textarea"] = raw_text
        st.session_state["auth_raw"] = raw_text
        st.session_state["ip_intel_textarea"] = raw_text
        st.session_state["ip_intel_email"] = raw_text
    elif email_text.strip():
        if st.session_state.get("raw_eml_text") != email_text:
            st.session_state["raw_eml_text"] = email_text
            st.session_state["parsed_eml"] = parse_eml_file(email_text)
            if not st.session_state.get("forensic_email"):
                st.session_state["forensic_email"] = email_text
                st.session_state["forensic_email_textarea"] = email_text
            if not st.session_state.get("auth_raw"):
                st.session_state["auth_raw"] = email_text

    # Word count & character count
    if email_text.strip():
        word_count = len(email_text.split())
        char_count = len(email_text)
        st.markdown(f"""
        <div style="display:flex; gap:1.5rem; padding: 0.3rem 0; font-family: 'Share Tech Mono', monospace; font-size: 0.8rem; color: #64748b;">
            <span>📝 Words: {word_count}</span>
            <span>🔤 Characters: {char_count}</span>
            <span>📄 Lines: {email_text.count(chr(10)) + 1}</span>
        </div>
        """, unsafe_allow_html=True)

    # Analyze button
    st.markdown("")
    analyze_clicked = st.button(
        "🔍 INITIATE THREAT SCAN",
        use_container_width=True,
        type="primary",
        disabled=not email_text.strip(),
    )

    # ─── Analysis Results ────────────────────────────────────────────────────────

    if analyze_clicked and email_text.strip():
        # Custom scanning animation
        scan_container = st.empty()
        progress_bar = st.progress(0)

        scan_phases = [
            ("🔍 Initializing threat analysis engine...", 0, 10),
            ("📋 Loading rule-based detection modules...", 10, 20),
            ("🔑 Scanning for phishing keywords...", 20, 30),
            ("🔗 Analyzing URLs and domain reputation...", 30, 40),
            ("⚡ Detecting urgency patterns...", 40, 50),
            ("🤖 Activating ML Neural Core...", 50, 60),
            ("🧠 Processing through neural network...", 60, 75),
            ("🔄 Running fusion algorithm...", 75, 85),
            ("📊 Generating threat assessment...", 85, 95),
            ("✅ Scan complete. Rendering results...", 95, 100),
        ]

        for phase_text, start, end in scan_phases:
            scan_container.markdown(
                f'<div class="scanning-text">{phase_text}</div>',
                unsafe_allow_html=True,
            )
            for i in range(start, end):
                time.sleep(0.01)
                progress_bar.progress(i + 1)

        scan_container.empty()
        progress_bar.empty()

        # Run analysis
        result = analyze_email(email_text, model, vectorizer)
        scan_id = f"email-scan-{int(time.time())}"
        st.session_state["current_investigation"] = {
            "type": "email",
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "verdict": result["verdict"],
            "score": result["combined_score"],
            "result": result,
        }

        # Persist to CaseStore
        save_scan_to_case_store(
            email_id=scan_id,
            verdict_class=result["verdict"],
            verdict_priority="high" if result["verdict"] == "phishing" else ("normal" if result["verdict"] == "suspicious" else "low"),
            combined_score=result["combined_score"],
            urls=result.get("features", {}).get("urls_found"),
            raw_headers=raw_eml_bytes.decode("utf-8", errors="ignore") if raw_eml_bytes else None,
            body_text=email_text,
        )

        result = analyze_email(email_text, model, vectorizer)

        # Update session stats
        st.session_state.total_scans += 1
        if result["verdict"] == "phishing":
            st.session_state.threats_detected += 1
        elif result["verdict"] == "safe":
            st.session_state.safe_emails += 1

        # Add to history
        st.session_state.scan_history.append({
            "preview": email_text.replace("\n", " ").strip()[:50],
            "verdict": result["verdict"],
            "score": result["combined_score"],
            "time": datetime.now().strftime("%H:%M"),
        })

        # ── Verdict Card ──
        verdict_class = f"verdict-{result['verdict']}"
        st.markdown(f"""
        <div class="verdict-card {verdict_class}">
            <div class="verdict-emoji">{result['verdict_emoji']}</div>
            <div class="verdict-text" style="color: {result['verdict_color']}">{result['verdict_text']}</div>
            <div class="verdict-score">THREAT LEVEL: {result['combined_score']}%</div>
        </div>
        """, unsafe_allow_html=True)

        # ── Score Breakdown ──
        st.markdown("""
        <div class="tech-panel">
            <h4>📊 Threat Score Breakdown</h4>
        </div>
        """, unsafe_allow_html=True)

        col_r, col_m, col_c = st.columns(3)
        with col_r:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-value" style="color: #00aaff;">{result['rule_score']}%</div>
                <div class="metric-label">Rule Engine</div>
            </div>
            """, unsafe_allow_html=True)

        with col_m:
            ml_display = f"{result['ml_score']}%" if result['ml_score'] is not None else "N/A"
            ml_color = "#9333ea" if result['ml_score'] is not None else "#384050"
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-value" style="color: {ml_color};">{ml_display}</div>
                <div class="metric-label">ML Neural Core</div>
            </div>
            """, unsafe_allow_html=True)

        with col_c:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-value" style="color: {result['verdict_color']};">{result['combined_score']}%</div>
                <div class="metric-label">Combined Threat</div>
            </div>
            """, unsafe_allow_html=True)

        # ── Threat Score Bar ──
        bar_color = result["verdict_color"]
        st.markdown(f"""
        <div class="score-bar-container">
            <div class="score-bar" style="width: {result['combined_score']}%; background: linear-gradient(90deg, #00ff88, #FFA500, #FF4444);"></div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Detailed Findings ──
        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown("""
            <div class="tech-panel">
                <h4>📋 Rule Engine Findings</h4>
            </div>
            """, unsafe_allow_html=True)
            for finding in result["rule_findings"]:
                st.markdown(f"""<div class="finding-item">{finding}</div>""", unsafe_allow_html=True)

        with col_right:
            st.markdown("""
            <div class="tech-panel">
                <h4>🤖 ML Neural Core Analysis</h4>
            </div>
            """, unsafe_allow_html=True)

            ml = result["ml_prediction"]
            if ml.get("error"):
                st.warning(f"⚠️ {ml['error']} — Using rule-based analysis only.")
            else:
                pred_label = ml["label"].capitalize()
                pred_conf = ml["confidence"] * 100
                label_emoji = "🚨" if ml["label"] == "phishing" else "✅"

                st.markdown(f"""
                <div class="info-card">
                    <h4>{label_emoji} Classification: {pred_label}</h4>
                    <p style="color: #e2e8f0; font-family: 'Share Tech Mono', monospace;">
                        Confidence: <strong style="color: #00ff88;">{pred_conf:.1f}%</strong>
                    </p>
                </div>
                """, unsafe_allow_html=True)

                # Probability bars
                if "probabilities" in ml:
                    for label, prob in ml["probabilities"].items():
                        color = "#FF4444" if label == "phishing" else "#00ff88"
                        st.markdown(f"""
                        <div style="margin: 0.5rem 0;">
                            <span style="color: #94a3b8; font-size: 0.85rem; font-family: 'Share Tech Mono', monospace;">
                                {label.capitalize()}: {prob*100:.1f}%
                            </span>
                            <div class="score-bar-container">
                                <div class="score-bar" style="width: {prob*100}%; background: {color};"></div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Extracted Features ──
        st.markdown("""
        <div class="tech-panel">
            <h4>🔎 Extracted Threat Indicators</h4>
        </div>
        """, unsafe_allow_html=True)

        features = result.get("features", {})
        feat_cols = st.columns(3)

        with feat_cols[0]:
            keywords = features.get("phishing_keywords", [])
            kw_html = '<br>'.join([f'• <span style="color:#FF6B6B">{k}</span>' for k in keywords]) if keywords else '• <span style="color:#00ff88">None detected</span>'
            st.markdown(f"""
            <div class="info-card">
                <h4>🔑 Keywords ({len(keywords)})</h4>
                <p style="color: #e2e8f0;">{kw_html}</p>
            </div>
            """, unsafe_allow_html=True)

        with feat_cols[1]:
            urls = features.get("urls_found", [])
            sus_urls = features.get("suspicious_urls", [])
            url_html = ""
            if urls:
                for u in urls:
                    if u in sus_urls:
                        url_html += f'• 🔴 <span style="color:#FF4444">{u}</span><br>'
                    else:
                        url_html += f'• <span style="color:#FFA500">{u}</span><br>'
            else:
                url_html = '• <span style="color:#00ff88">No URLs found</span>'
            st.markdown(f"""
            <div class="info-card">
                <h4>🔗 URLs Found ({len(urls)})</h4>
                <p style="color: #e2e8f0;">{url_html}</p>
            </div>
            """, unsafe_allow_html=True)

        with feat_cols[2]:
            urgency = features.get("urgency_phrases", [])
            money = features.get("money_references", [])
            caps = features.get("caps_words", [])
            urgency_html = '<br>'.join([f'• <span style="color:#FFA500">{u}</span>' for u in urgency]) if urgency else 'None'
            st.markdown(f"""
            <div class="info-card">
                <h4>⚡ Other Indicators</h4>
                <p style="color: #e2e8f0;">
                    <strong style="color:#00aaff;">Urgency:</strong><br>{urgency_html}<br><br>
                    <strong style="color:#00aaff;">Money refs:</strong> {', '.join(money) if money else 'None'}<br><br>
                    <strong style="color:#00aaff;">CAPS words:</strong> {', '.join(caps[:5]) if caps else 'None'}
                </p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Safety Tips Based on Verdict ──
        st.markdown("""
        <div class="tech-panel">
            <h4>💡 Security Recommendations</h4>
        </div>
        """, unsafe_allow_html=True)

        if result["verdict"] == "phishing":
            tips = [
                ("🚫 DO NOT CLICK", "Do not click any links or download attachments from this email."),
                ("🗑️ DELETE IMMEDIATELY", "Move this email to spam/trash and report it as phishing."),
                ("🔐 VERIFY DIRECTLY", "If the email claims to be from a company, contact them directly via their official website."),
                ("🔑 CHECK YOUR ACCOUNTS", "If you already clicked a link or entered info, change your passwords immediately."),
            ]
        elif result["verdict"] == "suspicious":
            tips = [
                ("⚠️ PROCEED WITH CAUTION", "This email has some suspicious elements. Verify the sender before taking action."),
                ("🔍 CHECK THE SENDER", "Look at the full email address — does it match the claimed organization?"),
                ("🔗 HOVER OVER LINKS", "Before clicking, hover over links to see the actual URL destination."),
            ]
        else:
            tips = [
                ("✅ LIKELY SAFE", "This email appears to be legitimate based on our analysis."),
                ("🛡️ STAY VIGILANT", "Always keep your security awareness up, even with seemingly safe emails."),
            ]

        tip_cols = st.columns(len(tips))
        for i, (title, desc) in enumerate(tips):
            with tip_cols[i]:
                st.markdown(f"""
                <div class="tip-card">
                    <div class="tip-title">{title}</div>
                    {desc}
                </div>
                """, unsafe_allow_html=True)

    elif analyze_clicked:
        st.warning("⚠️ Please enter or paste an email to analyze.")

# ─── URL Analysis Tab ────────────────────────────────────────────────────────

with url_tab:
    st.markdown("""
    <div class="tech-panel">
        <h4>🔗 Quick URL Samples</h4>
    </div>
    """, unsafe_allow_html=True)

    ucol1, ucol2, ucol3 = st.columns(3)
    with ucol1:
        if st.button("🚨 Phishing URL", use_container_width=True, type="secondary", key="url_phish"):
            st.session_state["url_input"] = SAMPLE_URL_PHISHING
    with ucol2:
        if st.button("⚠️ Suspicious URL", use_container_width=True, type="secondary", key="url_sus"):
            st.session_state["url_input"] = SAMPLE_URL_SUSPICIOUS
    with ucol3:
        if st.button("✅ Safe URL", use_container_width=True, type="secondary", key="url_safe"):
            st.session_state["url_input"] = SAMPLE_URL_SAFE

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="tech-panel">
        <h4>🔗 URL Input Terminal</h4>
    </div>
    """, unsafe_allow_html=True)

    url_text = st.text_input(
        "Enter the URL you want to analyze:",
        value=st.session_state.get("url_input", ""),
        placeholder=">> Paste URL here for threat analysis...",
        label_visibility="collapsed",
    )

    st.markdown("")
    url_analyze_clicked = st.button(
        "🔍 INITIATE URL SCAN",
        use_container_width=True,
        type="primary",
        disabled=not (url_text and url_text.strip()),
        key="url_scan_btn",
    )

    if url_analyze_clicked and url_text.strip():
        scan_container = st.empty()
        progress_bar = st.progress(0)
        url_phases = [
            ("🔍 Initializing URL analysis engine...", 0, 15),
            ("🌐 Parsing URL components...", 15, 30),
            ("🔗 Checking domain reputation...", 30, 50),
            ("🛡️ Analyzing TLD and subdomains...", 50, 65),
            ("🔎 Scanning for phishing patterns...", 65, 80),
            ("📊 Generating threat assessment...", 80, 95),
            ("✅ Scan complete. Rendering results...", 95, 100),
        ]
        for phase_text, start, end in url_phases:
            scan_container.markdown(f'<div class="scanning-text">{phase_text}</div>', unsafe_allow_html=True)
            for i in range(start, end):
                time.sleep(0.02)
                progress_bar.progress(i + 1)
        result = analyze_url(url_text.strip())
        norm_url = normalize_url_or_domain(url_text.strip())
        scan_id = f"url-scan-{int(time.time())}"
        st.session_state["current_investigation"] = {
            "type": "url",
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "verdict": result["verdict"],
            "score": result["combined_score"],
            "result": result,
        }

        save_scan_to_case_store(
            email_id=scan_id,
            verdict_class=result["verdict"],
            verdict_priority="high" if result["verdict"] == "phishing" else ("normal" if result["verdict"] == "suspicious" else "low"),
            combined_score=result["combined_score"],
            sender_domain=norm_url.get("hostname", ""),
            urls=[url_text.strip()],
        )

        st.session_state.total_scans += 1

        if result["verdict"] == "phishing":
            st.session_state.threats_detected += 1
        elif result["verdict"] == "safe":
            st.session_state.safe_emails += 1

        st.session_state.scan_history.append({
            "preview": "🔗 " + url_text.strip()[:45],
            "verdict": result["verdict"],
            "score": result["combined_score"],
            "time": datetime.now().strftime("%H:%M"),
        })

        # Verdict Card
        verdict_class = f"verdict-{result['verdict']}"
        st.markdown(f"""
        <div class="verdict-card {verdict_class}">
            <div class="verdict-emoji">{result['verdict_emoji']}</div>
            <div class="verdict-text" style="color: {result['verdict_color']}">{result['verdict_text']}</div>
            <div class="verdict-score">THREAT LEVEL: {result['combined_score']}%</div>
        </div>
        """, unsafe_allow_html=True)

        # Score
        st.markdown("""
        <div class="tech-panel"><h4>📊 Threat Score</h4></div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-value" style="color: {result['verdict_color']};">{result['combined_score']}%</div>
            <div class="metric-label">Rule Engine Score</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="score-bar-container">
            <div class="score-bar" style="width: {result['combined_score']}%; background: linear-gradient(90deg, #00ff88, #FFA500, #FF4444);"></div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # Findings
        st.markdown("""
        <div class="tech-panel"><h4>📋 URL Analysis Findings</h4></div>
        """, unsafe_allow_html=True)
        for finding in result["rule_findings"]:
            st.markdown(f'<div class="finding-item">{finding}</div>', unsafe_allow_html=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # URL Feature Indicators
        st.markdown("""
        <div class="tech-panel"><h4>🔎 Extracted URL Indicators</h4></div>
        """, unsafe_allow_html=True)

        features = result.get("features", {})
        uf_cols = st.columns(3)

        with uf_cols[0]:
            protocol = "HTTPS ✅" if features.get("uses_https") else "HTTP ⚠️"
            ip_status = "Yes 🔴" if features.get("is_ip") else "No ✅"
            st.markdown(f"""
            <div class="info-card">
                <h4>🌐 Connection</h4>
                <p style="color: #e2e8f0;">
                    <strong style="color:#00aaff;">Protocol:</strong> {protocol}<br><br>
                    <strong style="color:#00aaff;">IP Address:</strong> {ip_status}<br><br>
                    <strong style="color:#00aaff;">Host:</strong> {features.get('hostname', 'N/A')}
                </p>
            </div>
            """, unsafe_allow_html=True)

        with uf_cols[1]:
            tld_status = f"Yes 🔴 ({features.get('matched_tld', '')})" if features.get("suspicious_tld") else "No ✅"
            kws = features.get("matched_keywords", [])
            kw_str = ", ".join(kws[:5]) if kws else "None"
            st.markdown(f"""
            <div class="info-card">
                <h4>🔑 Domain Analysis</h4>
                <p style="color: #e2e8f0;">
                    <strong style="color:#00aaff;">Suspicious TLD:</strong> {tld_status}<br><br>
                    <strong style="color:#00aaff;">Subdomains:</strong> {features.get('subdomain_count', 0)}<br><br>
                    <strong style="color:#00aaff;">Phishing keywords:</strong> {kw_str}
                </p>
            </div>
            """, unsafe_allow_html=True)

        with uf_cols[2]:
            at_status = "Yes 🔴" if features.get("has_at_sign") else "No ✅"
            port_status = "Yes 🟠" if features.get("has_port") else "No ✅"
            st.markdown(f"""
            <div class="info-card">
                <h4>⚡ Other Indicators</h4>
                <p style="color: #e2e8f0;">
                    <strong style="color:#00aaff;">Hyphens:</strong> {features.get('hyphen_count', 0)}<br><br>
                    <strong style="color:#00aaff;">@ Symbol:</strong> {at_status}<br><br>
                    <strong style="color:#00aaff;">Non-std Port:</strong> {port_status}<br><br>
                    <strong style="color:#00aaff;">Length:</strong> {features.get('url_length', 0)} chars
                </p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # Tips
        st.markdown("""
        <div class="tech-panel"><h4>💡 Security Recommendations</h4></div>
        """, unsafe_allow_html=True)

        if result["verdict"] == "phishing":
            tips = [
                ("🚫 DO NOT VISIT", "Do not open this URL in any browser. It shows strong phishing indicators."),
                ("🗑️ REPORT IT", "Report this URL to your IT security team or to Google Safe Browsing."),
                ("🔐 ALREADY VISITED?", "If you entered credentials, change your passwords immediately."),
            ]
        elif result["verdict"] == "suspicious":
            tips = [
                ("⚠️ USE CAUTION", "This URL has suspicious characteristics. Verify before visiting."),
                ("🔍 VERIFY DOMAIN", "Check if the domain matches the legitimate organization's website."),
            ]
        else:
            tips = [
                ("✅ LIKELY SAFE", "This URL appears legitimate based on our analysis."),
                ("🛡️ STAY ALERT", "Always verify URLs before entering sensitive information."),
            ]

        tip_cols = st.columns(len(tips))
        for i, (title, desc) in enumerate(tips):
            with tip_cols[i]:
                st.markdown(f"""
                <div class="tip-card">
                    <div class="tip-title">{title}</div>
                    {desc}
                </div>
                """, unsafe_allow_html=True)

    elif url_analyze_clicked:
        st.warning("⚠️ Please enter a URL to analyze.")

# ─── Social Engineering Analysis Tab ─────────────────────────────────────────

with se_tab:
    # Sample buttons
    st.markdown("""
    <div class="tech-panel">
        <h4>🕵️ Attack Type Samples</h4>
    </div>
    """, unsafe_allow_html=True)

    # Row 1: first 5 samples
    se_keys_row1 = list(SE_SAMPLES.keys())[:5]
    se_cols1 = st.columns(len(se_keys_row1))
    for i, key in enumerate(se_keys_row1):
        label, text = SE_SAMPLES[key]
        with se_cols1[i]:
            if st.button(label, use_container_width=True, type="secondary", key=f"se_{key}"):
                st.session_state["se_input"] = text

    # Row 2: remaining samples
    se_keys_row2 = list(SE_SAMPLES.keys())[5:]
    se_cols2 = st.columns(len(se_keys_row2))
    for i, key in enumerate(se_keys_row2):
        label, text = SE_SAMPLES[key]
        with se_cols2[i]:
            if st.button(label, use_container_width=True, type="secondary", key=f"se_{key}"):
                st.session_state["se_input"] = text

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # Input section
    st.markdown("""
    <div class="tech-panel">
        <h4>✍️ Message Input Terminal</h4>
        <p style="color: #64748b; font-size: 0.85rem; margin: 0; font-family: 'Share Tech Mono', monospace;">
            Paste any suspicious message — email, SMS, chat, or social media message
        </p>
    </div>
    """, unsafe_allow_html=True)

    se_text = st.text_area(
        "Enter the message to analyze for social engineering:",
        value=st.session_state.get("se_input", ""),
        height=220,
        placeholder=">> Paste suspicious message here for social engineering analysis...",
        label_visibility="collapsed",
        key="se_textarea",
    )

    # Word/char count
    if se_text.strip():
        word_count = len(se_text.split())
        char_count = len(se_text)
        st.markdown(f"""
        <div style="display:flex; gap:1.5rem; padding: 0.3rem 0; font-family: 'Share Tech Mono', monospace; font-size: 0.8rem; color: #64748b;">
            <span>📝 Words: {word_count}</span>
            <span>🔤 Characters: {char_count}</span>
            <span>📄 Lines: {se_text.count(chr(10)) + 1}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("")
    se_analyze_clicked = st.button(
        "🕵️ ANALYZE SOCIAL ENGINEERING TACTICS",
        use_container_width=True,
        type="primary",
        disabled=not se_text.strip(),
        key="se_scan_btn",
    )

    # ── Analysis Results ──────────────────────────────────────────────────────

    if se_analyze_clicked and se_text.strip():
        # Scanning animation
        scan_container = st.empty()
        progress_bar = st.progress(0)

        se_phases = [
            ("🔍 Initializing social engineering analysis engine...", 0, 10),
            ("🎭 Loading attack type classifiers...", 10, 20),
            ("🔑 Scanning for phishing indicators...", 20, 30),
            ("🎯 Detecting targeted attack patterns...", 30, 40),
            ("👔 Checking for authority impersonation...", 40, 50),
            ("🧠 Analyzing psychological manipulation tactics...", 50, 65),
            ("📊 Scoring attack type probabilities...", 65, 80),
            ("🔎 Extracting evidence and tactic markers...", 80, 90),
            ("📋 Generating threat classification report...", 90, 100),
        ]

        for phase_text, start, end in se_phases:
            scan_container.markdown(
                f'<div class="scanning-text">{phase_text}</div>',
                unsafe_allow_html=True,
            )
            for i in range(start, end):
                time.sleep(0.02)
                progress_bar.progress(i + 1)

        scan_container.empty()
        progress_bar.empty()

        # Run analysis
        result = analyze_social_engineering(se_text)
        scan_id = f"se-scan-{int(time.time())}"
        st.session_state["current_investigation"] = {
            "type": "social_engineering",
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "verdict": result["risk_level"],
            "score": result["overall_risk"],
            "result": result,
        }

        save_scan_to_case_store(
            email_id=scan_id,
            verdict_class="phishing" if result["risk_level"] in ("critical", "high") else ("suspicious" if result["risk_level"] == "moderate" else "safe"),
            verdict_priority="high" if result["risk_level"] in ("critical", "high") else "normal",
            combined_score=result["overall_risk"],
            body_text=se_text,
        )

        # Update session stats

        st.session_state.total_scans += 1
        if result["risk_level"] in ("critical", "high"):
            st.session_state.threats_detected += 1
        elif result["risk_level"] == "safe":
            st.session_state.safe_emails += 1

        # Add to history
        primary_name = result["primary_attack"]["name"] if result["primary_attack"] else "No attack"
        st.session_state.scan_history.append({
            "preview": f"🕵️ {primary_name}: " + se_text.replace("\n", " ").strip()[:30],
            "verdict": "phishing" if result["risk_level"] in ("critical", "high") else ("suspicious" if result["risk_level"] in ("moderate",) else "safe"),
            "score": result["overall_risk"],
            "time": datetime.now().strftime("%H:%M"),
        })

        # ── Risk Verdict Card ──
        risk_class_map = {
            "critical": "verdict-phishing",
            "high": "verdict-phishing",
            "moderate": "verdict-suspicious",
            "low": "verdict-suspicious",
            "safe": "verdict-safe",
        }
        verdict_class = risk_class_map.get(result["risk_level"], "verdict-safe")

        st.markdown(f"""
        <div class="verdict-card {verdict_class}">
            <div class="verdict-emoji">{result['risk_emoji']}</div>
            <div class="verdict-text" style="color: {result['risk_color']}">{result['risk_text']}</div>
            <div class="verdict-score">RISK LEVEL: {result['overall_risk']}%</div>
        </div>
        """, unsafe_allow_html=True)

        # ── Aggregate Risk Gauge (Odometer) + Detection Confidence Chart ──
        st.markdown("""
        <div class="tech-panel">
            <h4>🎛️ Aggregate Risk Assessment</h4>
        </div>
        """, unsafe_allow_html=True)

        gauge_col, chart_col = st.columns(2)

        with gauge_col:
            # CSS Odometer gauge
            risk_val = result['overall_risk']
            # Needle rotation: 0% = -90deg (left), 100% = 90deg (right)
            needle_deg = -90 + (risk_val / 100) * 180
            risk_color = result['risk_color']
            risk_label = result['risk_level'].upper()

            st.markdown(f"""
            <div style="
                background: rgba(10, 15, 30, 0.8);
                border: 1px solid rgba(0,255,136,0.1);
                border-radius: 16px;
                padding: 1.5rem 1rem;
                backdrop-filter: blur(20px);
                position: relative;
                overflow: hidden;
            ">
                <div style="
                    position: absolute;
                    top: 0; left: 0; right: 0;
                    height: 2px;
                    background: linear-gradient(90deg, transparent, {risk_color}, transparent);
                    opacity: 0.5;
                "></div>
                <div class="gauge-container">
                    <div class="gauge-bg"></div>
                    <div class="gauge-needle" style="transform: rotate({needle_deg}deg);"></div>
                    <div class="gauge-labels">
                        <span>0</span>
                        <span>25</span>
                        <span>50</span>
                        <span>75</span>
                        <span>100</span>
                    </div>
                </div>
                <div class="gauge-value" style="color: {risk_color}; text-shadow: 0 0 20px {risk_color}40;">
                    {risk_val}%
                </div>
                <div class="gauge-label-text">{risk_label}</div>
            </div>
            """, unsafe_allow_html=True)

        with chart_col:
            # Plotly Radar Chart — Detection Confidence Scores
            ranked = result.get("ranked_attacks", [])
            all_scores = result.get("attack_scores", {})

            # Build radar data from all attack types
            from utils import ATTACK_TYPES
            radar_labels = []
            radar_values = []
            radar_colors = []
            for aid, atype in ATTACK_TYPES.items():
                radar_labels.append(atype["name"])
                radar_values.append(all_scores.get(aid, 0))
                radar_colors.append(atype["color"])

            fig = go.Figure()

            fig.add_trace(go.Scatterpolar(
                r=radar_values + [radar_values[0]],  # close the polygon
                theta=radar_labels + [radar_labels[0]],
                fill='toself',
                fillcolor='rgba(0, 255, 136, 0.08)',
                line=dict(color='#00ff88', width=2),
                marker=dict(
                    color=radar_colors + [radar_colors[0]],
                    size=8,
                    line=dict(color='#0a0f1e', width=1),
                ),
                name='Confidence',
                hovertemplate='%{theta}: %{r:.0f}%<extra></extra>',
            ))

            fig.update_layout(
                polar=dict(
                    bgcolor='rgba(10, 15, 30, 0.0)',
                    radialaxis=dict(
                        visible=True,
                        range=[0, 100],
                        showticklabels=True,
                        tickfont=dict(size=9, color='#64748b', family='Share Tech Mono'),
                        gridcolor='rgba(0, 255, 136, 0.08)',
                        linecolor='rgba(0, 255, 136, 0.08)',
                    ),
                    angularaxis=dict(
                        tickfont=dict(size=10, color='#94a3b8', family='Share Tech Mono'),
                        gridcolor='rgba(0, 255, 136, 0.08)',
                        linecolor='rgba(0, 255, 136, 0.12)',
                    ),
                ),
                showlegend=False,
                paper_bgcolor='rgba(10, 15, 30, 0.8)',
                plot_bgcolor='rgba(10, 15, 30, 0.0)',
                margin=dict(l=50, r=50, t=30, b=30),
                height=320,
                font=dict(family='Share Tech Mono'),
            )

            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Primary Attack Type ──
        primary = result.get("primary_attack")
        if primary:
            st.markdown(f"""
            <div class="tech-panel">
                <h4>🎯 Primary Attack Classification</h4>
            </div>
            """, unsafe_allow_html=True)

            st.markdown(f"""
            <div style="
                background: linear-gradient(135deg, {primary['color']}15, {primary['color']}05);
                border: 1px solid {primary['color']}40;
                border-radius: 16px;
                padding: 1.5rem;
                margin: 0.5rem 0;
                text-align: center;
            ">
                <div style="font-size: 3rem; margin-bottom: 0.5rem;">{primary['icon']}</div>
                <div style="
                    font-family: 'Orbitron', monospace;
                    font-size: 1.4rem;
                    font-weight: 700;
                    color: {primary['color']};
                    letter-spacing: 2px;
                    text-transform: uppercase;
                    margin-bottom: 0.3rem;
                ">{primary['name']}</div>
                <div style="
                    font-family: 'Share Tech Mono', monospace;
                    color: #94a3b8;
                    font-size: 0.9rem;
                    margin-bottom: 0.8rem;
                ">CONFIDENCE: {primary['confidence']:.0f}%</div>
                <div style="
                    color: #c8d6e5;
                    font-size: 0.95rem;
                    max-width: 600px;
                    margin: 0 auto;
                    line-height: 1.6;
                ">{primary['description']}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Attack Type Probability Breakdown ──
        if ranked:
            st.markdown("""
            <div class="tech-panel">
                <h4>📊 Attack Type Probability Breakdown</h4>
            </div>
            """, unsafe_allow_html=True)

            # Horizontal bar chart with Plotly
            bar_attacks = [a for a in ranked if a["confidence"] >= 5]
            if bar_attacks:
                bar_attacks_rev = list(reversed(bar_attacks))  # bottom to top
                bar_fig = go.Figure()
                bar_fig.add_trace(go.Bar(
                    y=[f"{a['icon']} {a['name']}" for a in bar_attacks_rev],
                    x=[a['confidence'] for a in bar_attacks_rev],
                    orientation='h',
                    marker=dict(
                        color=[a['color'] for a in bar_attacks_rev],
                        line=dict(color='rgba(255,255,255,0.1)', width=1),
                    ),
                    text=[f"{a['confidence']:.0f}%" for a in bar_attacks_rev],
                    textposition='outside',
                    textfont=dict(color='#c8d6e5', size=11, family='Share Tech Mono'),
                    hovertemplate='%{y}: %{x:.0f}%<extra></extra>',
                ))
                bar_fig.update_layout(
                    paper_bgcolor='rgba(10, 15, 30, 0.8)',
                    plot_bgcolor='rgba(10, 15, 30, 0.0)',
                    xaxis=dict(
                        range=[0, 115],
                        showgrid=True,
                        gridcolor='rgba(0, 255, 136, 0.06)',
                        tickfont=dict(color='#64748b', size=10, family='Share Tech Mono'),
                        title=dict(text='Confidence %', font=dict(color='#64748b', size=10, family='Share Tech Mono')),
                    ),
                    yaxis=dict(
                        tickfont=dict(color='#e2e8f0', size=11, family='Share Tech Mono'),
                    ),
                    margin=dict(l=10, r=30, t=10, b=40),
                    height=max(200, len(bar_attacks) * 45 + 60),
                    showlegend=False,
                    font=dict(family='Share Tech Mono'),
                )
                st.plotly_chart(bar_fig, use_container_width=True, config={'displayModeBar': False})

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Psychological Tactics Detected ──
        tactics = result.get("tactics_detected", {})
        tactics_evidence = result.get("tactics_evidence", {})

        if tactics:
            st.markdown("""
            <div class="tech-panel">
                <h4>🧠 Psychological Manipulation Tactics Detected</h4>
            </div>
            """, unsafe_allow_html=True)

            # Display tactics in a grid
            tactic_items = list(tactics.items())
            tactic_cols_count = min(3, len(tactic_items))
            tactic_col_groups = [tactic_items[i:i + tactic_cols_count] for i in range(0, len(tactic_items), tactic_cols_count)]

            for group in tactic_col_groups:
                cols = st.columns(tactic_cols_count)
                for idx, (tid, tinfo) in enumerate(group):
                    with cols[idx]:
                        evidence_items = tactics_evidence.get(tid, [])
                        evidence_html = ""
                        for ev in evidence_items[:2]:
                            if ev["snippet"]:
                                evidence_html += f'<div style="background: rgba(255,255,255,0.03); border-left: 2px solid {tinfo["color"]}80; padding: 0.4rem 0.6rem; margin: 0.4rem 0; border-radius: 0 6px 6px 0; font-size: 0.8rem; color: #94a3b8; font-style: italic;">"{ev["snippet"]}"</div>'

                        st.markdown(f"""
                        <div style="
                            background: rgba(10, 15, 30, 0.8);
                            border: 1px solid {tinfo['color']}30;
                            border-radius: 14px;
                            padding: 1.2rem;
                            margin: 0.3rem 0;
                            backdrop-filter: blur(10px);
                            position: relative;
                            overflow: hidden;
                        ">
                            <div style="
                                position: absolute;
                                top: 0; left: 0; right: 0;
                                height: 2px;
                                background: linear-gradient(90deg, transparent, {tinfo['color']}, transparent);
                                opacity: 0.6;
                            "></div>
                            <div style="text-align: center; margin-bottom: 0.5rem;">
                                <span style="font-size: 1.8rem;">{tinfo['icon']}</span>
                            </div>
                            <div style="
                                font-family: 'Orbitron', monospace;
                                color: {tinfo['color']};
                                font-size: 0.75rem;
                                letter-spacing: 1px;
                                text-transform: uppercase;
                                text-align: center;
                                margin-bottom: 0.3rem;
                            ">{tinfo['name']}</div>
                            <div style="
                                font-family: 'Share Tech Mono', monospace;
                                color: #64748b;
                                font-size: 0.7rem;
                                text-align: center;
                                margin-bottom: 0.5rem;
                            ">STRENGTH: {tinfo['confidence']:.0f}%</div>
                            <div style="
                                color: #94a3b8;
                                font-size: 0.82rem;
                                line-height: 1.5;
                                text-align: center;
                                margin-bottom: 0.5rem;
                            ">{tinfo['description']}</div>
                            {evidence_html}
                        </div>
                        """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Evidence Excerpts ──
        if ranked and any(a.get("evidence") for a in ranked[:3]):
            st.markdown("""
            <div class="tech-panel">
                <h4>🔎 Tactic Evidence — Matched Indicators</h4>
            </div>
            """, unsafe_allow_html=True)

            for attack in ranked[:3]:
                evidence = attack.get("evidence", [])
                if not evidence:
                    continue
                st.markdown(f"""
                <div style="margin: 0.5rem 0;">
                    <div style="
                        font-family: 'Orbitron', monospace;
                        font-size: 0.75rem;
                        color: {attack['color']};
                        letter-spacing: 1px;
                        text-transform: uppercase;
                        margin-bottom: 0.4rem;
                    ">{attack['icon']} {attack['name']} — Matched Phrases</div>
                </div>
                """, unsafe_allow_html=True)

                for ev in evidence:
                    if ev["snippet"]:
                        st.markdown(f"""
                        <div class="finding-item" style="border-left-color: {attack['color']}80;">
                            <strong style="color: {attack['color']};">🔑 "{ev['phrase']}"</strong><br>
                            <span style="color: #94a3b8; font-size: 0.85rem; font-style: italic;">Context: "{ev['snippet']}"</span>
                        </div>
                        """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Know Your Enemy — Educational Panel ──
        if primary:
            st.markdown("""
            <div class="tech-panel">
                <h4>📚 Know Your Enemy</h4>
            </div>
            """, unsafe_allow_html=True)

            kye_cols = st.columns(2)

            with kye_cols[0]:
                st.markdown(f"""
                <div class="info-card" style="border-color: {primary['color']}20;">
                    <h4 style="color: {primary['color']};">⚙️ How This Attack Works</h4>
                    <p style="color: #c8d6e5; font-size: 0.92rem; line-height: 1.7;">
                        {primary['how_it_works']}
                    </p>
                </div>
                """, unsafe_allow_html=True)

            with kye_cols[1]:
                defense_html = ""
                for tip in primary["defense"]:
                    defense_html += f'<div style="display: flex; gap: 0.5rem; margin: 0.5rem 0; align-items: start;"><span style="color: #00ff88; flex-shrink: 0;">▸</span><span style="color: #c8d6e5; font-size: 0.92rem; line-height: 1.5;">{tip}</span></div>'

                st.markdown(f"""
                <div class="info-card" style="border-color: #00ff8820;">
                    <h4 style="color: #00ff88;">🛡️ How to Defend Yourself</h4>
                    {defense_html}
                </div>
                """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Security Recommendations ──
        st.markdown("""
        <div class="tech-panel">
            <h4>💡 Security Recommendations</h4>
        </div>
        """, unsafe_allow_html=True)

        if result["risk_level"] in ("critical", "high"):
            tips = [
                ("🚨 HIGH ALERT", "This message contains strong social engineering indicators. Do NOT respond or click any links."),
                ("🗑️ QUARANTINE", "Move this message to spam/trash and report it to your IT security team immediately."),
                ("🔐 VERIFY SOURCE", "If the message claims to be from someone you know, verify through a separate communication channel."),
                ("📋 DOCUMENT IT", "Screenshot the message for your records before deleting — it may be needed for investigation."),
            ]
        elif result["risk_level"] == "moderate":
            tips = [
                ("⚠️ PROCEED CAREFULLY", "This message has suspicious elements. Verify the sender before taking any action."),
                ("🔍 VERIFY IDENTITY", "Contact the claimed sender through official channels to confirm the request."),
                ("🛡️ TRUST YOUR INSTINCTS", "If something feels off, it probably is. When in doubt, don't act."),
            ]
        elif result["risk_level"] == "low":
            tips = [
                ("🟡 LOW RISK", "Minor indicators detected. Exercise normal caution when responding."),
                ("👀 STAY AWARE", "Keep your security awareness up — even subtle attacks can be effective."),
            ]
        else:
            tips = [
                ("✅ LIKELY SAFE", "This message appears to be legitimate based on our analysis."),
                ("🛡️ STAY VIGILANT", "Continue to apply good security habits with all communications."),
            ]

        tip_cols = st.columns(len(tips))
        for i, (title, desc) in enumerate(tips):
            with tip_cols[i]:
                st.markdown(f"""
                <div class="tip-card">
                    <div class="tip-title">{title}</div>
                    {desc}
                </div>
                """, unsafe_allow_html=True)

    elif se_analyze_clicked:
        st.warning("⚠️ Please enter a message to analyze.")

# ─── GeoLocation & Forensic Intelligence Tab ─────────────────────────────────

with forensics_tab:
    # Sample inputs
    st.markdown("""
    <div class="tech-panel">
        <h4>🔬 GeoLocation & Forensic Intelligence</h4>
        <p style="color: #64748b; font-size: 0.85rem; margin: 0; font-family: 'Share Tech Mono', monospace;">
            Analyze domain infrastructure, geographic threat intelligence, email headers, and digital forensics
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Input options
    forensics_mode = st.radio(
        "Analysis Mode",
        ["🌐 Domain Geolocation", "📧 Email Header Forensics", "🔍 Full Forensic Report"],
        horizontal=True,
        key="forensics_mode",
    )

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    if forensics_mode == "🌐 Domain Geolocation":
        # Domain geolocation input
        st.markdown("""
        <div class="tech-panel">
            <h4>🌐 Domain Geolocation Analysis</h4>
            <p style="color: #64748b; font-size: 0.85rem; margin: 0;">
                Resolve DNS records, geolocate IP addresses, and assess geographic threat intelligence
            </p>
        </div>
        """, unsafe_allow_html=True)

        # Sample domains
        geo_sample_cols = st.columns(4)
        with geo_sample_cols[0]:
            if st.button("🚨 Suspicious Domain", use_container_width=True, type="secondary", key="geo_phish"):
                st.session_state["geo_domain"] = "secure-banking-verify.tk"
        with geo_sample_cols[1]:
            if st.button("🎯 Random XYZ Domain", use_container_width=True, type="secondary", key="geo_xyz"):
                st.session_state["geo_domain"] = "amaz0n-account-verify.xyz"
        with geo_sample_cols[2]:
            if st.button("✅ Google.com", use_container_width=True, type="secondary", key="geo_google"):
                st.session_state["geo_domain"] = "www.google.com"
        with geo_sample_cols[3]:
            if st.button("🏢 Microsoft", use_container_width=True, type="secondary", key="geo_microsoft"):
                st.session_state["geo_domain"] = "www.microsoft.com"

        geo_domain = st.text_input(
            "Enter domain to analyze:",
            value=st.session_state.get("geo_domain", ""),
            placeholder=">> Enter domain (e.g., example.com)...",
            label_visibility="collapsed",
            key="geo_domain_input",
        )

        geo_scan_clicked = st.button(
            "🔍 INITIATE GEOLOCATION SCAN",
            use_container_width=True,
            type="primary",
            disabled=not (geo_domain and geo_domain.strip()),
            key="geo_scan_btn",
        )

        if geo_scan_clicked and geo_domain.strip():
            domain = geo_domain.strip()

            # Scanning animation
            scan_container = st.empty()
            progress_bar = st.progress(0)
            geo_phases = [
                ("🔍 Initializing geolocation engine...", 0, 10),
                ("🌐 Resolving DNS records...", 10, 25),
                ("📍 Looking up IP geolocation data...", 25, 50),
                ("🗺️ Building geographic threat map...", 50, 70),
                ("🛡️ Cross-referencing threat intelligence...", 70, 85),
                ("📊 Generating geographic threat assessment...", 85, 95),
                ("✅ Scan complete. Rendering results...", 95, 100),
            ]
            for phase_text, start, end in geo_phases:
                scan_container.markdown(f'<div class="scanning-text">{phase_text}</div>', unsafe_allow_html=True)
                for i in range(start, end):
                    time.sleep(0.02)
                    progress_bar.progress(i + 1)
            scan_container.empty()
            progress_bar.empty()

            # Run geolocation analysis
            with st.spinner("Resolving domain and geolocating IPs..."):
                geo_result = geolocate_domain(domain)
                threat_assessment = assess_geo_threat(geo_result)
                map_data = generate_map_data(domain, geo_result)

            scan_id = f"geo-scan-{int(time.time())}"
            st.session_state["current_investigation"] = {
                "type": "geolocation",
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "verdict": threat_assessment["threat_level"],
                "score": threat_assessment["score"],
                "result": geo_result,
            }

            save_scan_to_case_store(
                email_id=scan_id,
                verdict_class="phishing" if threat_assessment["threat_level"] == "high" else ("suspicious" if threat_assessment["threat_level"] == "moderate" else "safe"),
                verdict_priority="high" if threat_assessment["threat_level"] == "high" else "normal",
                combined_score=threat_assessment["score"],
                sender_domain=geo_result.get("domain", domain),
                ips=[p["ip"] for p in map_data],
            )

            # Update session stats

            st.session_state.total_scans += 1
            if threat_assessment["threat_level"] in ("high",):
                st.session_state.threats_detected += 1
            elif threat_assessment["threat_level"] == "safe":
                st.session_state.safe_emails += 1

            st.session_state.scan_history.append({
                "preview": f"🌐 {domain}",
                "verdict": "phishing" if threat_assessment["threat_level"] == "high" else ("suspicious" if threat_assessment["threat_level"] == "moderate" else "safe"),
                "score": threat_assessment["score"],
                "time": datetime.now().strftime("%H:%M"),
            })

            # ── Verdict Card ──
            verdict_class_map = {
                "high": "verdict-phishing",
                "moderate": "verdict-suspicious",
                "low": "verdict-safe",
                "safe": "verdict-safe",
            }
            verdict_class = verdict_class_map.get(threat_assessment["threat_level"], "verdict-safe")

            st.markdown(f"""
            <div class="verdict-card {verdict_class}">
                <div class="verdict-emoji">{threat_assessment['threat_emoji']}</div>
                <div class="verdict-text" style="color: {threat_assessment['threat_color']}">{threat_assessment['threat_text']}</div>
                <div class="verdict-score">GEOGRAPHIC THREAT: {threat_assessment['score']}%</div>
            </div>
            """, unsafe_allow_html=True)

            # ── Threat Findings ──
            st.markdown("""
            <div class="tech-panel">
                <h4>📋 Geographic Threat Findings</h4>
            </div>
            """, unsafe_allow_html=True)
            for finding in threat_assessment["findings"]:
                st.markdown(f'<div class="finding-item">{finding}</div>', unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Map Visualization ──
            if map_data:
                st.markdown("""
                <div class="tech-panel">
                    <h4>🗺️ Geographic Distribution Map</h4>
                </div>
                """, unsafe_allow_html=True)

                fig_map = build_geolocation_map_figure(map_data, height=400)
                st.plotly_chart(fig_map, use_container_width=True, config={"displayModeBar": False})

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── IP Details Table ──
            dns_data = geo_result.get("dns", {})
            geolocations = geo_result.get("geolocations", [])

            if geolocations:
                st.markdown("""
                <div class="tech-panel">
                    <h4>📍 IP Geolocation Details</h4>
                </div>
                """, unsafe_allow_html=True)

                for geo in geolocations:
                    threat_color_map = {"critical": "#FF0000", "high": "#FF4444", "moderate": "#FFA500", "low": "#00ff88", "unknown": "#64748b"}
                    tc = threat_color_map.get(geo.get("threat_level", "unknown"), "#64748b")

                    st.markdown(f"""
                    <div class="info-card">
                        <h4 style="color: {tc};">📍 {geo['ip']} — {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}</h4>
                        <p style="color: #e2e8f0;">
                            <strong style="color:#00aaff;">ISP:</strong> {geo.get('isp', 'N/A')}<br>
                            <strong style="color:#00aaff;">Org:</strong> {geo.get('org', 'N/A')}<br>
                            <strong style="color:#00aaff;">AS:</strong> {geo.get('as_info', 'N/A')}<br>
                            <strong style="color:#00aaff;">Timezone:</strong> {geo.get('timezone', 'N/A')}<br>
                            <strong style="color:#00aaff;">Reverse DNS:</strong> {geo.get('reverse_dns', 'N/A')}<br>
                            <strong style="color:#00aaff;">Proxy/VPN:</strong> {'⚠️ Yes' if geo.get('is_proxy') else '✅ No'}<br>
                            <strong style="color:#00aaff;">Threat Level:</strong> <span style="color: {tc};">{geo.get('threat_level', 'unknown').upper()}</span>
                        </p>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── DNS Records ──
            if dns_data:
                st.markdown("""
                <div class="tech-panel">
                    <h4>🌐 DNS Records</h4>
                </div>
                """, unsafe_allow_html=True)

                dns_cols = st.columns(2)

                with dns_cols[0]:
                    a_records = dns_data.get("a_records", [])
                    mx_records = dns_data.get("mx_records", [])
                    a_html = '<br>'.join([f'• <span style="color:#00ff88">{r}</span>' for r in a_records]) if a_records else '• <span style="color:#64748b">None</span>'
                    mx_html = '<br>'.join([f'• <span style="color:#00aaff">{r.get("exchange", "")} (pri: {r.get("priority", "")})</span>' for r in mx_records]) if mx_records else '• <span style="color:#64748b">None</span>'
                    st.markdown(f"""
                    <div class="info-card">
                        <h4>🔗 A Records ({len(a_records)})</h4>
                        <p style="color: #e2e8f0;">{a_html}</p>
                    </div>
                    """, unsafe_allow_html=True)
                    st.markdown(f"""
                    <div class="info-card">
                        <h4>📧 MX Records ({len(mx_records)})</h4>
                        <p style="color: #e2e8f0;">{mx_html}</p>
                    </div>
                    """, unsafe_allow_html=True)

                with dns_cols[1]:
                    ns_records = dns_data.get("ns_records", [])
                    txt_records = dns_data.get("txt_records", [])
                    ns_html = '<br>'.join([f'• <span style="color:#9333ea">{r}</span>' for r in ns_records]) if ns_records else '• <span style="color:#64748b">None</span>'
                    txt_html = '<br>'.join([f'• <span style="color:#64748b;font-size:0.8rem;">{r[:80]}{"..." if len(r) > 80 else ""}</span>' for r in txt_records[:5]]) if txt_records else '• <span style="color:#64748b">None</span>'
                    st.markdown(f"""
                    <div class="info-card">
                        <h4>🏷️ NS Records ({len(ns_records)})</h4>
                        <p style="color: #e2e8f0;">{ns_html}</p>
                    </div>
                    """, unsafe_allow_html=True)
                    st.markdown(f"""
                    <div class="info-card">
                        <h4>📝 TXT Records ({len(txt_records)})</h4>
                        <p style="color: #e2e8f0;">{txt_html}</p>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Tips ──
            st.markdown("""
            <div class="tech-panel">
                <h4>💡 Geographic Intelligence Recommendations</h4>
            </div>
            """, unsafe_allow_html=True)

            if threat_assessment["threat_level"] == "high":
                tips = [
                    ("🔴 HIGH RISK", "Domain resolves to IPs in high-risk regions. Exercise extreme caution."),
                    ("🌐 VPN/PROXY", "If proxy detected, true origin is masked — cannot verify legitimate location."),
                    ("🛡️ VERIFY DOMAIN", "Cross-check this domain against the organization you expect to hear from."),
                ]
            elif threat_assessment["threat_level"] == "moderate":
                tips = [
                    ("⚠️ MODERATE RISK", "Some geographic red flags detected. Investigate further before trusting."),
                    ("🔍 CHECK INFRASTRUCTURE", "Review DNS records and IP locations for anomalies."),
                ]
            else:
                tips = [
                    ("✅ LOW RISK", "Geographic and DNS analysis shows no significant red flags."),
                    ("🛡️ STAY VIGILANT", "Geographic safety doesn't guarantee legitimacy — verify through other means."),
                ]

            tip_cols = st.columns(len(tips))
            for i, (title, desc) in enumerate(tips):
                with tip_cols[i]:
                    st.markdown(f"""
                    <div class="tip-card">
                        <div class="tip-title">{title}</div>
                        {desc}
                    </div>
                    """, unsafe_allow_html=True)

    elif forensics_mode == "📧 Email Header Forensics":
        # Email header forensics input
        st.markdown("""
        <div class="tech-panel">
            <h4>📧 Email Header Forensic Analysis</h4>
            <p style="color: #64748b; font-size: 0.85rem; margin: 0;">
                Analyze email headers for spoofing, authentication failures, routing anomalies, and forensic evidence
            </p>
        </div>
        """, unsafe_allow_html=True)

        # Sample emails with headers
        st.markdown("""
        <div class="tech-panel">
            <h4>📋 Sample Email Headers</h4>
        </div>
        """, unsafe_allow_html=True)

        header_sample_cols = st.columns(3)
        with header_sample_cols[0]:
            if st.button("📧 Phishing with Headers", use_container_width=True, type="secondary", key="forensic_phish"):
                st.session_state["forensic_email"] = SAMPLE_FORENSIC_PHISHING
        with header_sample_cols[1]:
            if st.button("📧 Safe with Headers", use_container_width=True, type="secondary", key="forensic_safe"):
                st.session_state["forensic_email"] = SAMPLE_FORENSIC_SAFE
        with header_sample_cols[2]:
            if st.button("📧 Spear Phish", use_container_width=True, type="secondary", key="forensic_spear"):
                st.session_state["forensic_email"] = SAMPLE_FORENSIC_SPEAR

        forensic_file = st.file_uploader(
            "Or upload a .eml/.txt file for forensic analysis",
            type=["eml", "txt"],
            help="Upload an email file to analyze its envelope headers and routing chain",
            key="forensic_file_uploader",
        )
        if forensic_file is not None:
            f_bytes = forensic_file.read()
            f_text = f_bytes.decode("utf-8", errors="ignore")
            f_parsed = parse_eml_file(f_bytes)
            st.session_state["raw_eml_bytes"] = f_bytes
            st.session_state["raw_eml_text"] = f_text
            st.session_state["parsed_eml"] = f_parsed
            st.session_state["forensic_email"] = f_text
            st.session_state["forensic_email_textarea"] = f_text
            st.session_state["full_forensic_textarea"] = f_text
            st.session_state["auth_raw"] = f_text
            st.session_state["ip_intel_textarea"] = f_text
            st.session_state["ip_intel_email"] = f_text
            st.info(f"📄 .EML File loaded for forensics: **{forensic_file.name}** (From: `{f_parsed['from_email'] or 'N/A'}`, Subject: `{f_parsed['subject'] or 'N/A'}`)")

        forensic_val = st.session_state.get("forensic_email") or st.session_state.get("raw_eml_text", "")
        forensic_email = st.text_area(
            "Paste the full email (with headers if available):",
            value=forensic_val,
            height=220,
            placeholder=">> Paste full email content including headers (From, To, Subject, Received, etc.)...",
            label_visibility="collapsed",
            key="forensic_email_textarea",
        )

        forensic_scan_clicked = st.button(
            "🔍 INITIATE EMAIL FORENSIC ANALYSIS",
            use_container_width=True,
            type="primary",
            disabled=not forensic_email.strip(),
            key="forensic_scan_btn",
        )

        if forensic_scan_clicked and forensic_email.strip():
            # Scanning animation
            scan_container = st.empty()
            progress_bar = st.progress(0)
            forensics_phases = [
                ("🔍 Initializing forensic analysis engine...", 0, 10),
                ("📧 Parsing email headers...", 10, 25),
                ("🔐 Checking SPF/DKIM/DMARC authentication...", 25, 40),
                ("🔗 Analyzing routing chain...", 40, 55),
                ("👤 Checking sender identity consistency...", 55, 70),
                ("🕵️ Running domain reputation checks...", 70, 85),
                ("📊 Generating forensic report...", 85, 95),
                ("✅ Analysis complete. Rendering results...", 95, 100),
            ]
            for phase_text, start, end in forensics_phases:
                scan_container.markdown(f'<div class="scanning-text">{phase_text}</div>', unsafe_allow_html=True)
                for i in range(start, end):
                    time.sleep(0.02)
                    progress_bar.progress(i + 1)
            scan_container.empty()
            progress_bar.empty()

            # Run forensic analysis
            with st.spinner("Performing forensic analysis..."):
                report = generate_forensic_report(email_text=forensic_email.strip())

            scan_id = f"forensic-scan-{int(time.time())}"
            st.session_state["current_investigation"] = {
                "type": "forensic",
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "verdict": report["risk_level"],
                "score": report["overall_score"],
                "result": report,
            }

            save_scan_to_case_store(
                email_id=scan_id,
                verdict_class="phishing" if report["risk_level"] in ("critical", "high") else ("suspicious" if report["risk_level"] == "moderate" else "safe"),
                verdict_priority="high" if report["risk_level"] in ("critical", "high") else "normal",
                combined_score=report["overall_score"],
                raw_headers=forensic_email.strip(),
            )

            # Update session stats
            st.session_state.total_scans += 1
            if report["risk_level"] in ("critical", "high"):
                st.session_state.threats_detected += 1
            elif report["risk_level"] == "safe":
                st.session_state.safe_emails += 1

            st.session_state.scan_history.append({
                "preview": f"📧 Forensic: {forensic_email[:35]}...",
                "verdict": "phishing" if report["risk_level"] in ("critical", "high") else ("suspicious" if report["risk_level"] == "moderate" else "safe"),
                "score": report["overall_score"],
                "time": datetime.now().strftime("%H:%M"),
            })

            # ── Verdict Card ──
            risk_color_map = {"critical": "#FF0000", "high": "#FF4444", "moderate": "#FFA500", "low": "#FFD700", "safe": "#00ff88"}
            risk_emoji_map = {"critical": "🚨", "high": "🔴", "moderate": "⚠️", "low": "🟡", "safe": "✅"}
            risk_text_map = {
                "critical": "Critical — Strong Forensic Anomalies",
                "high": "High Risk — Forensic Evidence of Tampering",
                "moderate": "Moderate — Some Forensic Concerns",
                "low": "Low — Minor Forensic Anomalies",
                "safe": "Safe — No Forensic Red Flags",
            }

            rl = report["risk_level"]
            rc = risk_color_map.get(rl, "#64748b")
            rv = risk_emoji_map.get(rl, "❓")
            rt = risk_text_map.get(rl, "Unknown")

            st.markdown(f"""
            <div class="verdict-card verdict-{rl if rl in ('high','critical') else ('suspicious' if rl == 'moderate' else 'safe')}">
                <div class="verdict-emoji">{rv}</div>
                <div class="verdict-text" style="color: {rc}">{rt}</div>
                <div class="verdict-score">FORENSIC SCORE: {report['overall_score']}%</div>
            </div>
            """, unsafe_allow_html=True)

            # ── Forensic Findings ──
            st.markdown("""
            <div class="tech-panel">
                <h4>📋 Forensic Findings</h4>
            </div>
            """, unsafe_allow_html=True)
            for finding in report["findings"]:
                st.markdown(f'<div class="finding-item">{finding}</div>', unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Email Header Details ──
            email_forensics = report.get("email_forensics")
            if email_forensics and not email_forensics.get("error"):
                headers_data = email_forensics.get("headers", {})
                analysis = email_forensics.get("analysis", {})
                forensic_data = analysis.get("forensic_data", {})

                st.markdown("""
                <div class="tech-panel">
                    <h4>📧 Parsed Email Headers</h4>
                </div>
                """, unsafe_allow_html=True)

                if not email_forensics.get("has_headers"):
                    st.warning("⚠️ No envelope headers detected in the pasted "
                               "input — it looks like body-only text. Header "
                               "forensics needs the raw headers (From, To, "
                               "Received, …). Paste a full .eml / raw header "
                               "block to get meaningful results.")
                else:
                    st.caption("Header-only analysis — message body content is "
                               "never scored here.")

                header_cols = st.columns(2)

                with header_cols[0]:
                    st.markdown(f"""
                    <div class="info-card">
                        <h4>👤 Sender Information</h4>
                        <p style="color: #e2e8f0;">
                            <strong style="color:#00aaff;">From:</strong> {headers_data.get('From', 'N/A')}<br>
                            <strong style="color:#00aaff;">Sender:</strong> {headers_data.get('Sender', 'N/A')}<br>
                            <strong style="color:#00aaff;">Reply-To:</strong> {headers_data.get('Reply-To', 'N/A')}<br>
                            <strong style="color:#00aaff;">Return-Path:</strong> {headers_data.get('Return-Path', 'N/A')}<br>
                            <strong style="color:#00aaff;">X-Originating-IP:</strong> {headers_data.get('X-Originating-IP', 'N/A')}
                        </p>
                    </div>
                    """, unsafe_allow_html=True)

                with header_cols[1]:
                    st.markdown(f"""
                    <div class="info-card">
                        <h4>📬 Envelope & Recipients</h4>
                        <p style="color: #e2e8f0;">
                            <strong style="color:#00aaff;">To:</strong> {headers_data.get('To', 'N/A')}<br>
                            <strong style="color:#00aaff;">Cc:</strong> {headers_data.get('Cc', 'N/A')}<br>
                            <strong style="color:#00aaff;">Bcc:</strong> {headers_data.get('Bcc', 'N/A')}<br>
                            <strong style="color:#00aaff;">Envelope-To:</strong> {headers_data.get('Envelope-To', headers_data.get('Delivered-To', headers_data.get('X-Original-To', 'N/A')))}
                        </p>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

                hcol3 = st.columns(2)

                with hcol3[0]:
                    st.markdown(f"""
                    <div class="info-card">
                        <h4>📄 Message Metadata</h4>
                        <p style="color: #e2e8f0;">
                            <strong style="color:#00aaff;">Subject:</strong> {headers_data.get('Subject', 'N/A')}<br>
                            <strong style="color:#00aaff;">Date:</strong> {headers_data.get('Date', 'N/A')}<br>
                            <strong style="color:#00aaff;">Message-ID:</strong> {headers_data.get('Message-ID', 'N/A')}
                        </p>
                    </div>
                    """, unsafe_allow_html=True)

                with hcol3[1]:
                    spf_result = forensic_data.get("spf_result", "unknown")
                    dkim_result = forensic_data.get("dkim_result", "unknown")
                    dmarc_result = forensic_data.get("dmarc_result", "unknown")
                    spf_color = "#00ff88" if spf_result == "pass" else "#FF4444" if spf_result == "fail" else "#FFA500"
                    dkim_color = "#00ff88" if dkim_result == "pass" else "#FF4444" if dkim_result == "fail" else "#FFA500"
                    dmarc_color = "#00ff88" if dmarc_result == "pass" else "#FF4444" if dmarc_result == "fail" else "#FFA500"

                    st.markdown(f"""
                    <div class="info-card">
                        <h4>🔐 Email Authentication</h4>
                        <p style="color: #e2e8f0;">
                            <strong style="color:#00aaff;">SPF:</strong> <span style="color:{spf_color};">{spf_result.upper()}</span><br>
                            <strong style="color:#00aaff;">DKIM:</strong> <span style="color:{dkim_color};">{dkim_result.upper()}</span><br>
                            <strong style="color:#00aaff;">DMARC:</strong> <span style="color:{dmarc_color};">{dmarc_result.upper()}</span><br>
                            <strong style="color:#00aaff;">Routing Hops:</strong> {forensic_data.get('routing_ips', []) and len(forensic_data.get('routing_ips', [])) or 'N/A'}<br>
                            <strong style="color:#00aaff;">X-Mailer:</strong> {forensic_data.get('x_mailer', 'N/A')}
                        </p>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Full raw header listing (detected headers for review) ──
            if email_forensics and not email_forensics.get("error"):
                with st.expander("🗂️ Every detected header — raw review"):
                    raw_headers = (email_forensics.get("raw_headers") or "").strip()
                    if raw_headers:
                        st.code(raw_headers, language="eml")
                    else:
                        st.caption("No headers detected in input.")

            # ── WHOIS & SSL Data (if domain found) ──
            whois_data = report.get("whois_data")
            ssl_data = report.get("ssl_data")

            if whois_data or ssl_data:
                st.markdown("""
                <div class="tech-panel">
                    <h4>🌐 Domain Intelligence</h4>
                </div>
                """, unsafe_allow_html=True)

                domain_cols = st.columns(2)

                with domain_cols[0]:
                    if whois_data:
                        age_display = f"{whois_data.get('domain_age_days', 'N/A')} days" if whois_data.get("domain_age_days") else "N/A"
                        recently = "⚠️ Yes — very new domain!" if whois_data.get("is_recently_registered") else "No"
                        ns_html = '<br>'.join([f'• {ns}' for ns in whois_data.get("name_servers", [])[:5]]) or "None"
                        st.markdown(f"""
                        <div class="info-card">
                            <h4>📋 WHOIS Intelligence</h4>
                            <p style="color: #e2e8f0;">
                                <strong style="color:#00aaff;">Registrar:</strong> {whois_data.get('registrar', 'N/A')}<br>
                                <strong style="color:#00aaff;">Created:</strong> {whois_data.get('creation_date', 'N/A')}<br>
                                <strong style="color:#00aaff;">Expires:</strong> {whois_data.get('expiration_date', 'N/A')}<br>
                                <strong style="color:#00aaff;">Domain Age:</strong> {age_display}<br>
                                <strong style="color:#00aaff;">Recently Registered:</strong> {recently}<br>
                                <strong style="color:#00aaff;">Country:</strong> {whois_data.get('registrant_country', 'N/A')}<br>
                                <strong style="color:#00aaff;">Org:</strong> {whois_data.get('registrant_org', 'N/A')}<br>
                                <strong style="color:#00aaff;">Name Servers:</strong><br>{ns_html}
                            </p>
                        </div>
                        """, unsafe_allow_html=True)

                with domain_cols[1]:
                    if ssl_data:
                        ssl_status = "✅ Valid" if ssl_data.get("has_ssl") else "❌ No SSL"
                        issuer = ssl_data.get("issuer", {}).get("organizationName", "N/A") if ssl_data.get("has_ssl") else "N/A"
                        expiry = ssl_data.get("not_after", "N/A") if ssl_data.get("has_ssl") else "N/A"
                        days_left = ssl_data.get("days_until_expiry")
                        days_display = f"{days_left} days" if days_left is not None else "N/A"
                        san_list = ssl_data.get("san_domains", [])[:5]
                        san_html = '<br>'.join([f'• {s}' for s in san_list]) or "None"
                        self_signed = "⚠️ Yes" if ssl_data.get("is_self_signed") else "No" if ssl_data.get("has_ssl") else "N/A"

                        st.markdown(f"""
                        <div class="info-card">
                            <h4>🔒 SSL/TLS Certificate</h4>
                            <p style="color: #e2e8f0;">
                                <strong style="color:#00aaff;">Status:</strong> {ssl_status}<br>
                                <strong style="color:#00aaff;">Issuer:</strong> {issuer}<br>
                                <strong style="color:#00aaff;">Expires:</strong> {expiry}<br>
                                <strong style="color:#00aaff;">Days Until Expiry:</strong> {days_display}<br>
                                <strong style="color:#00aaff;">Self-Signed:</strong> {self_signed}<br>
                                <strong style="color:#00aaff;">SAN Domains:</strong><br>{san_html}
                            </p>
                        </div>
                        """, unsafe_allow_html=True)

                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Tips ──
            st.markdown("""
            <div class="tech-panel">
                <h4>💡 Forensic Investigation Recommendations</h4>
            </div>
            """, unsafe_allow_html=True)

            if report["risk_level"] in ("critical", "high"):
                tips = [
                    ("🚨 HIGH ALERT", "Forensic analysis reveals strong evidence of email tampering or spoofing."),
                    ("📧 PRESERVE EVIDENCE", "Save the original email with full headers for incident response."),
                    ("🔐 SECURE ACCOUNTS", "If you interacted with this email, change passwords and enable MFA immediately."),
                    ("📋 REPORT IT", "Report this email to your IT security team and email provider."),
                ]
            elif report["risk_level"] == "moderate":
                tips = [
                    ("⚠️ INVESTIGATE", "Some forensic anomalies detected — verify the sender through separate channels."),
                    ("🔍 CHECK AUTH", "Review SPF/DKIM/DMARC results for authentication failures."),
                ]
            else:
                tips = [
                    ("✅ CLEAN", "No significant forensic anomalies detected."),
                    ("🛡️ VERIFY", "Always cross-reference with other analysis modules for complete assessment."),
                ]

            tip_cols = st.columns(len(tips))
            for i, (title, desc) in enumerate(tips):
                with tip_cols[i]:
                    st.markdown(f"""
                    <div class="tip-card">
                        <div class="tip-title">{title}</div>
                        {desc}
                    </div>
                    """, unsafe_allow_html=True)

    elif forensics_mode == "🔍 Full Forensic Report":
        # Full forensic report (email + domain analysis combined)
        st.markdown("""
        <div class="tech-panel">
            <h4>🔍 Full Forensic Intelligence Report</h4>
            <p style="color: #64748b; font-size: 0.85rem; margin: 0;">
                Comprehensive analysis combining email headers, domain WHOIS, SSL certificates, DNS records, and geographic intelligence
            </p>
        </div>
        """, unsafe_allow_html=True)

        full_val = st.session_state.get("forensic_email") or st.session_state.get("raw_eml_text", "")
        full_input = st.text_area(
            "Paste the full email (with headers) — domain will be extracted automatically:",
            value=full_val,
            height=220,
            placeholder=">> Paste full email content for comprehensive forensic analysis...",
            label_visibility="collapsed",
            key="full_forensic_textarea",
        )

        full_scan_clicked = st.button(
            "🔍 INITIATE FULL FORENSIC REPORT",
            use_container_width=True,
            type="primary",
            disabled=not full_input.strip(),
            key="full_forensic_scan_btn",
        )

        if full_scan_clicked and full_input.strip():
            # Scanning animation
            scan_container = st.empty()
            progress_bar = st.progress(0)
            full_phases = [
                ("🔍 Initializing full forensic engine...", 0, 8),
                ("📧 Parsing email headers...", 8, 16),
                ("🔐 Checking SPF/DKIM/DMARC...", 16, 24),
                ("🔗 Analyzing routing chain...", 24, 32),
                ("👤 Checking sender identity...", 32, 40),
                ("🌐 Extracting sender domain...", 40, 48),
                ("📋 Running WHOIS lookup...", 48, 56),
                ("🔒 Analyzing SSL certificate...", 56, 64),
                ("📍 Resolving DNS records...", 64, 72),
                ("🗺️ Geolocating IP addresses...", 72, 80),
                ("🛡️ Cross-referencing threat intelligence...", 80, 88),
                ("📊 Generating comprehensive report...", 88, 95),
                ("✅ Report complete. Rendering results...", 95, 100),
            ]
            for phase_text, start, end in full_phases:
                scan_container.markdown(f'<div class="scanning-text">{phase_text}</div>', unsafe_allow_html=True)
                for i in range(start, end):
                    time.sleep(0.02)
                    progress_bar.progress(i + 1)
            scan_container.empty()
            progress_bar.empty()

            # Run full analysis
            with st.spinner("Performing comprehensive forensic analysis..."):
                report = generate_forensic_report(email_text=full_input.strip())
                sender_domain = (
                    report.get("sender_domain")
                    or (report.get("whois_data") or {}).get("domain")
                    or (report.get("email_forensics") or {}).get("analysis", {}).get("forensic_data", {}).get("sender_domain")
                )
                if not sender_domain:
                    urls_in_text = extract_urls(full_input)
                    if urls_in_text:
                        sender_domain = normalize_url_or_domain(urls_in_text[0]).get("hostname")

                geo_result = None
                threat_assessment = None
                map_data = []

                if sender_domain:
                    try:
                        geo_result = geolocate_domain(sender_domain)
                        threat_assessment = assess_geo_threat(geo_result)
                        map_data = generate_map_data(sender_domain, geo_result)
                    except Exception:
                        pass

                if not map_data:
                    try:
                        ip_ext = extract_ips_from_email(full_input)
                        if ip_ext and not ip_ext.get("no_ip"):
                            ip_res = run_ip_intelligence(ip_ext)
                            for rec in ip_res.get("ip_results", []):
                                geo = rec.get("geo") or {}
                                if geo.get("ok") and geo.get("latitude") is not None and geo.get("longitude") is not None:
                                    map_data.append({
                                        "ip": rec["ip"],
                                        "lat": geo["latitude"],
                                        "lon": geo["longitude"],
                                        "city": geo.get("city", "Unknown"),
                                        "country": geo.get("country", "Unknown"),
                                        "isp": geo.get("isp", "Unknown"),
                                        "threat": rec.get("risk_level", "unknown"),
                                        "color": "#FF4444" if rec.get("risk_level") == "high" else ("#FFA500" if rec.get("risk_level") == "moderate" else "#00ff88"),
                                        "is_proxy": bool(geo.get("hosting")),
                                    })
                            if map_data and not threat_assessment:
                                threat_assessment = {
                                    "score": int(ip_res["summary"]["max_score"]),
                                    "threat_level": ip_res["summary"]["risk_level"],
                                    "threat_color": "#FF4444" if ip_res["summary"]["risk_level"] == "high" else "#FFA500",
                                    "threat_emoji": "🔴" if ip_res["summary"]["risk_level"] == "high" else "⚠️",
                                    "findings": [f"📍 Geolocated {len(map_data)} public IP(s) from email headers"],
                                }
                    except Exception:
                        pass

            # Update session stats
            st.session_state.total_scans += 1
            combined_score = max(report["overall_score"], threat_assessment["score"] if threat_assessment else 0)
            if combined_score >= 35:
                st.session_state.threats_detected += 1
            elif combined_score < 10:
                st.session_state.safe_emails += 1

            # ── Overall Verdict ──
            combined_level = "safe"
            if combined_score >= 60:
                combined_level = "phishing"
            elif combined_score >= 35:
                combined_level = "suspicious"

            scan_id = f"full-forensic-scan-{int(time.time())}"
            st.session_state["current_investigation"] = {
                "type": "full_forensic",
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "verdict": combined_level,
                "score": combined_score,
                "result": report,
            }

            save_scan_to_case_store(
                email_id=scan_id,
                verdict_class=combined_level,
                verdict_priority="high" if combined_level == "phishing" else ("normal" if combined_level == "suspicious" else "low"),
                combined_score=combined_score,
                sender_domain=sender_domain or "",
                ips=[p["ip"] for p in map_data] if map_data else None,
                raw_headers=full_input.strip(),
            )

            risk_emoji_map = {"critical": "🚨", "high": "🔴", "moderate": "⚠️", "low": "🟡", "safe": "✅"}
            risk_color_map = {"critical": "#FF0000", "high": "#FF4444", "moderate": "#FFA500", "low": "#FFD700", "safe": "#00ff88"}
            verdict_class_map = {"phishing": "verdict-phishing", "suspicious": "verdict-suspicious", "safe": "verdict-safe"}

            st.markdown(f"""
            <div class="verdict-card {verdict_class_map.get(combined_level, 'verdict-safe')}">
                <div class="verdict-emoji">{risk_emoji_map.get(report['risk_level'], '❓')}</div>
                <div class="verdict-text" style="color: {risk_color_map.get(report['risk_level'], '#64748b')}">COMPREHENSIVE FORENSIC ASSESSMENT</div>
                <div class="verdict-score">COMBINED SCORE: {combined_score}% | FORENSIC: {report['overall_score']}% | GEOGRAPHIC: {threat_assessment['score'] if threat_assessment else 0}%</div>
            </div>
            """, unsafe_allow_html=True)

            st.session_state.scan_history.append({
                "preview": f"🔍 Full forensic: {full_input[:30]}...",
                "verdict": combined_level,
                "score": combined_score,
                "time": datetime.now().strftime("%H:%M"),
            })

            # ── Score Breakdown ──
            st.markdown("""
            <div class="tech-panel">
                <h4>📊 Analysis Score Breakdown</h4>
            </div>
            """, unsafe_allow_html=True)

            score_cols = st.columns(3)
            with score_cols[0]:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-value" style="color: {risk_color_map.get(report['risk_level'], '#64748b')};">{report['overall_score']}%</div>
                    <div class="metric-label">Forensic Score</div>
                </div>
                """, unsafe_allow_html=True)
            with score_cols[1]:
                geo_score = threat_assessment["score"] if threat_assessment else 0
                geo_color = threat_assessment["threat_color"] if threat_assessment else "#64748b"
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-value" style="color: {geo_color};">{geo_score}%</div>
                    <div class="metric-label">Geographic Score</div>
                </div>
                """, unsafe_allow_html=True)
            with score_cols[2]:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-value" style="color: {risk_color_map.get(combined_level, '#64748b')};">{combined_score}%</div>
                    <div class="metric-label">Combined Threat</div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown(f"""
            <div class="score-bar-container">
                <div class="score-bar" style="width: {combined_score}%; background: linear-gradient(90deg, #00ff88, #FFA500, #FF4444);"></div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── All Forensic Findings ──
            st.markdown("""
            <div class="tech-panel">
                <h4>📋 All Forensic Findings</h4>
            </div>
            """, unsafe_allow_html=True)

            all_findings = report.get("findings", []) + (threat_assessment.get("findings", []) if threat_assessment else [])
            for finding in all_findings:
                st.markdown(f'<div class="finding-item">{finding}</div>', unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Email Authentication ──
            email_forensics = report.get("email_forensics")
            if email_forensics and not email_forensics.get("error"):
                analysis = email_forensics.get("analysis", {})
                forensic_data = analysis.get("forensic_data", {})

                st.markdown("""
                <div class="tech-panel">
                    <h4>🔐 Email Authentication Results</h4>
                </div>
                """, unsafe_allow_html=True)

                auth_cols = st.columns(3)
                for i, (key, label) in enumerate([("spf_result", "SPF"), ("dkim_result", "DKIM"), ("dmarc_result", "DMARC")]):
                    result_val = forensic_data.get(key, "unknown")
                    color = "#00ff88" if result_val == "pass" else "#FF4444" if result_val == "fail" else "#FFA500"
                    with auth_cols[i]:
                        st.markdown(f"""
                        <div class="metric-box">
                            <div class="metric-value" style="color: {color};">{result_val.upper()}</div>
                            <div class="metric-label">{label} Result</div>
                        </div>
                        """, unsafe_allow_html=True)

                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Map ──
            if map_data:
                st.markdown("""
                <div class="tech-panel">
                    <h4>🗺️ Geographic Distribution</h4>
                </div>
                """, unsafe_allow_html=True)

                fig_map = build_geolocation_map_figure(map_data, height=350)
                st.plotly_chart(fig_map, use_container_width=True, config={"displayModeBar": False})
                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── WHOIS & SSL ──
            whois_data = report.get("whois_data")
            ssl_data = report.get("ssl_data")

            if whois_data or ssl_data:
                intel_cols = st.columns(2)
                with intel_cols[0]:
                    if whois_data:
                        age_display = f"{whois_data.get('domain_age_days', 'N/A')} days" if whois_data.get("domain_age_days") else "N/A"
                        st.markdown(f"""
                        <div class="info-card">
                            <h4>📋 WHOIS Intelligence</h4>
                            <p style="color: #e2e8f0;">
                                <strong style="color:#00aaff;">Registrar:</strong> {whois_data.get('registrar', 'N/A')}<br>
                                <strong style="color:#00aaff;">Created:</strong> {whois_data.get('creation_date', 'N/A')}<br>
                                <strong style="color:#00aaff;">Expires:</strong> {whois_data.get('expiration_date', 'N/A')}<br>
                                <strong style="color:#00aaff;">Domain Age:</strong> {age_display}<br>
                                <strong style="color:#00aaff;">Country:</strong> {whois_data.get('registrant_country', 'N/A')}
                            </p>
                        </div>
                        """, unsafe_allow_html=True)
                with intel_cols[1]:
                    if ssl_data and ssl_data.get("has_ssl"):
                        issuer = ssl_data.get("issuer", {}).get("organizationName", "N/A")
                        st.markdown(f"""
                        <div class="info-card">
                            <h4>🔒 SSL Certificate</h4>
                            <p style="color: #e2e8f0;">
                                <strong style="color:#00aaff;">Issuer:</strong> {issuer}<br>
                                <strong style="color:#00aaff;">Expires:</strong> {ssl_data.get('not_after', 'N/A')}<br>
                                <strong style="color:#00aaff;">Self-Signed:</strong> {'Yes ⚠️' if ssl_data.get('is_self_signed') else 'No'}<br>
                                <strong style="color:#00aaff;">SAN Count:</strong> {len(ssl_data.get('san_domains', []))}
                            </p>
                        </div>
                        """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Comprehensive Recommendations ──
            st.markdown("""
            <div class="tech-panel">
                <h4>💡 Comprehensive Security Recommendations</h4>
            </div>
            """, unsafe_allow_html=True)

            tips = [
                ("📧 PRESERVE", "Save the original email with full headers as evidence."),
                ("🔐 RESET", "If you interacted with this email, change passwords and enable MFA."),
                ("📋 REPORT", "Report the email to your IT security team and email provider."),
                ("🛡️ MONITOR", "Monitor your accounts for suspicious activity for the next 30 days."),
            ]

            tip_cols = st.columns(len(tips))
            for i, (title, desc) in enumerate(tips):
                with tip_cols[i]:
                    st.markdown(f"""
                    <div class="tip-card">
                        <div class="tip-title">{title}</div>
                        {desc}
                    </div>
                    """, unsafe_allow_html=True)


# ─── IP Intelligence & Geolocation Tab ───────────────────────────────────────

with ip_intel_tab:
    st.markdown("""
    <div class="tech-panel">
        <h4>🛰️ IP Intelligence & Geolocation</h4>
        <p style="color: #64748b; font-size: 0.85rem; margin: 0; font-family: 'Share Tech Mono', monospace;">
            Extract IPs from email headers → classify → geolocate public IPs → explainable risk assessment
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ── GeoIP provider configuration status ──
    _geoip_cfg = get_geoip_config()
    if _geoip_cfg["enabled"]:
        st.success(f"🌐 {_geoip_cfg['message']}")
    else:
        st.info(f"ℹ️ {_geoip_cfg['message']}")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # Sample loaders
    if "ip_intel_textarea" not in st.session_state:
        st.session_state["ip_intel_textarea"] = st.session_state.get("ip_intel_email", SAMPLE_IP_INTEL)

    sample_cols = st.columns(3)
    with sample_cols[0]:
        if st.button("📧 Sample with Headers", use_container_width=True, type="secondary"):
            st.session_state["ip_intel_textarea"] = SAMPLE_IP_INTEL
            st.session_state["ip_intel_email"] = SAMPLE_IP_INTEL
    with sample_cols[1]:
        if st.button("🔄 Use Email Analysis Input", use_container_width=True, type="secondary"):
            val = st.session_state.get("raw_eml_text", "") or st.session_state.get("email_input", "")
            st.session_state["ip_intel_textarea"] = val
            st.session_state["ip_intel_email"] = val
    with sample_cols[2]:
        if st.button("📥 Use Forensic Input", use_container_width=True, type="secondary"):
            val = st.session_state.get("raw_eml_text", "") or st.session_state.get("forensic_email", "")
            st.session_state["ip_intel_textarea"] = val
            st.session_state["ip_intel_email"] = val

    ip_intel_file = st.file_uploader(
        "Or upload a .eml/.txt email file",
        type=["eml", "txt", "json"],
        help="Upload an email file — we only extract headers/IPs, raw contents are not stored.",
    )
    if ip_intel_file is not None:
        try:
            file_bytes = ip_intel_file.read()
            file_content_str = file_bytes.decode("utf-8", errors="ignore")
            i_parsed = parse_eml_file(file_bytes)
            st.session_state["raw_eml_bytes"] = file_bytes
            st.session_state["raw_eml_text"] = file_content_str
            st.session_state["parsed_eml"] = i_parsed
            st.session_state["ip_intel_textarea"] = file_content_str
            st.session_state["ip_intel_email"] = file_content_str
            st.session_state["forensic_email"] = file_content_str
            st.session_state["forensic_email_textarea"] = file_content_str
            st.session_state["full_forensic_textarea"] = file_content_str
            st.session_state["auth_raw"] = file_content_str
            st.info(f"📄 Loaded **{ip_intel_file.name}** ({len(file_content_str)} characters)")
        except Exception as e:
            st.warning(f"Could not read file: {e}")

    ip_intel_text = st.text_area(
        "Paste an email (with headers) for IP intelligence:",
        value=st.session_state.get("ip_intel_textarea", SAMPLE_IP_INTEL),
        height=240,
        placeholder=">> Paste full email including Received, X-Originating-IP, X-Sender-IP headers...",
        label_visibility="collapsed",
        key="ip_intel_textarea",
    )

    ip_intel_scan = st.button(
        "🔍 ANALYZE IP INTELLIGENCE",
        use_container_width=True,
        type="primary",
        disabled=not ip_intel_text.strip(),
        key="ip_intel_scan_btn",
    )


    if ip_intel_scan and ip_intel_text.strip():
        import pandas as pd

        # Scanning animation
        scan_container = st.empty()
        progress_bar = st.progress(0)
        ip_phases = [
            ("🔍 Initializing IP intelligence engine...", 0, 10),
            ("📧 Parsing email headers...", 10, 25),
            ("📍 Extracting candidate IP addresses...", 25, 40),
            ("🧮 Validating & classifying IPs...", 40, 55),
            ("🌐 Querying GeoIP provider (public IPs only)...", 55, 75),
            ("🕵️ Running reputation & risk analysis...", 75, 90),
            ("🕸️ Building threat graph...", 90, 98),
            ("✅ Analysis complete. Rendering results...", 98, 100),
        ]
        for phase_text, start, end in ip_phases:
            scan_container.markdown(f'<div class="scanning-text">{phase_text}</div>', unsafe_allow_html=True)
            for i in range(start, end):
                time.sleep(0.015)
                progress_bar.progress(i + 1)
        scan_container.empty()
        progress_bar.empty()

        # Exceptions here must NEVER crash the dashboard.
        try:
            extraction = extract_ips_from_email(ip_intel_text.strip())
        except Exception as e:
            st.error(f"IP extraction failed: {e}")
            extraction = None

        if extraction is None:
            pass
        elif extraction.get("no_ip"):
            st.warning("🚫 No IP addresses found in the email headers. Nothing to analyze.")
        else:
            with st.spinner("Querying GeoIP provider and assessing risk..."):

                result = run_ip_intelligence(extraction)
                urls = extract_urls(ip_intel_text)
                graph = ThreatGraph().build_from_ip_intel(
                    extraction["email_id"], result["ip_results"], urls=urls)

            scan_id = extraction.get("email_id") or f"ip-scan-{int(time.time())}"
            st.session_state["current_investigation"] = {
                "type": "ip_intelligence",
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "verdict": result["summary"]["risk_level"],
                "score": result["summary"]["max_score"],
                "result": result,
            }

            save_scan_to_case_store(
                email_id=scan_id,
                verdict_class="phishing" if result["summary"]["risk_level"] == "high" else ("suspicious" if result["summary"]["risk_level"] == "moderate" else "safe"),
                verdict_priority="high" if result["summary"]["risk_level"] == "high" else "normal",
                combined_score=result["summary"]["max_score"],
                ip_risk=result["summary"]["risk_level"],
                urls=urls,
                ips=[r["ip"] for r in result["ip_results"]],
                raw_headers=ip_intel_text.strip(),
            )

            st.session_state.total_scans += 1


            risk_level = result["summary"]["risk_level"]
            risk_color_map = {"high": "#FF4444", "moderate": "#FFA500", "low": "#FFD700"}
            risk_emoji_map = {"high": "🔴", "moderate": "🟠", "low": "🟡"}

            # ── Verdict card ──
            st.markdown(f"""
            <div class="verdict-card verdict-{'phishing' if risk_level == 'high' else ('suspicious' if risk_level == 'moderate' else 'safe')}">
                <div class="verdict-emoji">{risk_emoji_map.get(risk_level, '🟡')}</div>
                <div class="verdict-text" style="color: {risk_color_map.get(risk_level, '#FFD700')}">
                    IP INTELLIGENCE — {risk_level.upper()} RISK INDICATORS
                </div>
                <div class="verdict-score">
                    {result['summary']['public_ips']} PUBLIC | {result['summary']['private_reserved_ips']} NON-PUBLIC |
                    {result['summary']['suspicious_ips']} SUSPICIOUS | MAX IP SCORE: {int(result['summary']['max_score'])}%
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("""
            <div style="text-align:center; color:#64748b; font-size:0.75rem; margin-top: -0.3rem;
                        font-family:'Share Tech Mono', monospace;">
                IP reputation is supporting evidence only — it does not by itself classify this email as phishing.
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Origin trust assessment (header-chronology + provider masking) ──
            if _HAS_NEW_MODULES:
                try:
                    origin = assess_origin(extraction, result["ip_results"])
                    anomalies = detect_header_anomalies(extraction)
                    oa = origin["assessment"]
                    if oa == "attributed":
                        o_emoji, o_color = "🎯", "#00ff88"
                    elif oa == "provider_masked":
                        o_emoji, o_color = "🎭", "#FFA500"
                    elif oa == "hosting_only":
                        o_emoji, o_color = "🏢", "#FFA500"
                    else:
                        o_emoji, o_color = "🚫", "#64748b"
                    st.markdown("""
                    <div class="tech-panel">
                        <h4>🎯 Origin Trust Assessment</h4>
                    </div>
                    """, unsafe_allow_html=True)
                    st.markdown(f"""
                    <div class="info-card" style="border-left: 3px solid {o_color};">
                        <h4 style="color: {o_color};">{o_emoji} {origin['assessment'].upper().replace('_', ' ')}</h4>
                        <p style="color:#c8d6e5;">{origin['summary']}</p>
                        <p style="color:#c8d6e5; font-size:0.85rem;">
                            <strong style="color:#00aaff;">Earliest reliable node:</strong>
                            {origin.get('earliest_reliable_ip') or 'None'}<br>
                            <strong style="color:#00aaff;">Masking providers:</strong>
                            {', '.join(origin.get('masking_providers') or ['None'])}
                        </p>
                    </div>
                    """, unsafe_allow_html=True)
                    if anomalies:
                        for a in anomalies:
                            st.markdown(f'<div class="finding-item">{a}</div>', unsafe_allow_html=True)
                    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                except Exception as e:
                    st.warning(f"Origin assessment skipped: {e}")

            # ── Summary metrics ──
            sum_cols = st.columns(4)
            for i, (label, value, color) in enumerate([
                ("Total IPs", result["summary"]["total_ips"], "#e2e8f0"),
                ("Public IPs", result["summary"]["public_ips"], "#00aaff"),
                ("Suspicious", result["summary"]["suspicious_ips"], "#FF4444"),
                ("Max Risk Score", f"{int(result['summary']['max_score'])}%", risk_color_map.get(risk_level, "#FFD700")),
            ]):
                with sum_cols[i]:
                    st.markdown(f"""
                    <div class="metric-box">
                        <div class="metric-value" style="color: {color};">{value}</div>
                        <div class="metric-label">{label}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Per-IP detail cards ──
            st.markdown("""
            <div class="tech-panel">
                <h4>📍 IP Address Detail</h4>
            </div>
            """, unsafe_allow_html=True)

            for rec in result["ip_results"]:
                geo = rec.get("geo") or {}
                rc = risk_color_map.get(rec["risk_level"], "#00ff88")
                geo_block = ""
                if geo.get("ok"):
                    geo_block += f"<strong style='color:#00aaff;'>Country:</strong> {geo.get('country') or 'N/A'}<br>"
                    geo_block += f"<strong style='color:#00aaff;'>Region:</strong> {geo.get('region') or 'N/A'}<br>"
                    geo_block += f"<strong style='color:#00aaff;'>City:</strong> {geo.get('city') or 'N/A'}<br>"
                    geo_block += f"<strong style='color:#00aaff;'>ISP:</strong> {geo.get('isp') or 'N/A'}<br>"
                    geo_block += f"<strong style='color:#00aaff;'>Organization:</strong> {geo.get('organization') or 'N/A'}<br>"
                    geo_block += f"<strong style='color:#00aaff;'>ASN:</strong> {geo.get('asn') or 'N/A'}<br>"
                    geo_block += f"<strong style='color:#00aaff;'>Timezone:</strong> {geo.get('timezone') or 'N/A'}<br>"
                    geo_block += f"<strong style='color:#00aaff;'>Hosting:</strong> {'⚠️ Yes (datacenter/provider)' if geo.get('hosting') else 'No'}<br>"
                    rep_display = format_ip_reputation_display(rec)
                    if rep_display:
                        geo_block += f"<strong style='color:#00aaff;'>Reputation:</strong> {rep_display}<br>"
                    elif geo.get("ok"):
                        geo_block += f"<strong style='color:#00aaff;'>Reputation:</strong> N/A<br>"
                elif rec["is_public"]:
                    geo_block = "<strong style='color:#64748b;'>Geolocation unavailable</strong>"
                    if geo.get("error"):
                        geo_block += f"<br><em style='color:#64748b; font-size:0.8rem;'>{geo['error']}</em>"
                else:
                    geo_block = f"<strong style='color:#64748b;'>{rec['type']} address — not sent to GeoIP API</strong>"

                sources_txt = ", ".join(f"{s['header']}" + (f" (hop {s['hop']})" if "hop" in s else "")
                                        for s in rec["sources"])

                indicators_html = "".join(
                    f'<div style="margin:0.2rem 0; color:#c8d6e5; font-size:0.85rem;">▸ {ind}</div>'
                    for ind in rec["indicators"])

                st.markdown(f"""
                <div class="info-card">
                    <h4 style="color: {rc};">🌐 {rec['ip']}
                        <span style="font-size:0.75rem; color:#64748b;">[IPv{rec['version']} — {rec['type_label']}]</span>
                        <span style="float:right; color:{rc}; font-family:'Share Tech Mono', monospace;">{rec['risk_level'].upper()} · {int(rec['score'])}%</span>
                    </h4>
                    <p style="color: #e2e8f0;">
                        <strong style="color:#00aaff;">Type:</strong> {rec['type_label']}<br>
                        <strong style="color:#00aaff;">Sources:</strong> {sources_txt}<br>
                        {geo_block}
                    </p>
                    <p style="color:#e2e8f0;">{indicators_html}</p>
                </div>
                """, unsafe_allow_html=True)

                # Explanation for suspicious IPs
                if rec["risk_level"] in ("high", "moderate"):
                    st.markdown(f"""
                    <div style="background: rgba(255, 68, 68, 0.06); border-left: 3px solid {rc};
                                border-radius: 0 10px 10px 0; padding: 0.8rem 1rem; margin: 0.2rem 0 0.8rem 0;">
                        <strong style="color:{rc}; font-family:'Orbitron', monospace; font-size:0.75rem;">🔎 FORENSIC EXPLANATION</strong><br>
                        <span style="color:#c8d6e5; font-size:0.88rem;">{rec['explanation']}</span>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── IP detail table ──
            table_rows = []
            for rec in result["ip_results"]:
                geo = rec.get("geo") or {}
                table_rows.append({
                    "IP": rec["ip"],
                    "Type": rec["type_label"],
                    "Country": geo.get("country"),
                    "Region": geo.get("region"),
                    "City": geo.get("city"),
                    "ISP": geo.get("isp"),
                    "Organization": geo.get("organization"),
                    "ASN": geo.get("asn"),
                    "Hosting": "Yes" if geo.get("hosting") else ("No" if geo.get("ok") else None),
                    "Reputation": format_ip_reputation_display(rec),
                    "Risk Level": rec["risk_level"].upper(),
                })
            df_ips = pd.DataFrame(table_rows)
            if not df_ips.empty:
                st.markdown("""
                <div class="tech-panel">
                    <h4>📊 IP Intelligence Summary</h4>
                </div>
                """, unsafe_allow_html=True)
                st.dataframe(df_ips, use_container_width=True, hide_index=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Map (only when valid coordinates exist) ──
            formatted_map_points = []
            for rec in result["ip_results"]:
                geo = rec.get("geo") or {}
                if geo.get("ok") and geo.get("latitude") is not None and geo.get("longitude") is not None:
                    formatted_map_points.append({
                        "ip": rec["ip"],
                        "lat": geo["latitude"],
                        "lon": geo["longitude"],
                        "city": geo.get("city", "Unknown"),
                        "country": geo.get("country", "Unknown"),
                        "isp": geo.get("isp", "Unknown"),
                        "threat": rec.get("risk_level", "unknown"),
                        "color": risk_color_map.get(rec.get("risk_level"), "#64748b"),
                        "is_proxy": bool(geo.get("hosting")),
                    })
            if formatted_map_points:
                st.markdown("""
                <div class="tech-panel">
                    <h4>🗺️ Probable Geographic/Network Context Map</h4>
                </div>
                """, unsafe_allow_html=True)
                fig_ip_map = build_geolocation_map_figure(formatted_map_points, height=380)
                st.plotly_chart(fig_ip_map, use_container_width=True, config={"displayModeBar": False})
                st.markdown("""
                <div style="color:#64748b; font-size:0.75rem; font-family:'Share Tech Mono', monospace;">
                    ⚠️ This reflects probable geographic/network context of infrastructure, not the attacker's exact physical location.
                </div>
                """, unsafe_allow_html=True)
                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Header correlation table ──
            if result["correlations"]:
                st.markdown("""
                <div class="tech-panel">
                    <h4>🔗 Header Correlation — Email → Header → IP → Network Context</h4>
                </div>
                """, unsafe_allow_html=True)
                df_corr = pd.DataFrame(result["correlations"])
                df_corr = df_corr[["email_id", "header", "ip", "country", "region",
                                   "city", "isp", "asn", "risk_level"]]
                st.dataframe(df_corr, use_container_width=True, hide_index=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Threat graph ──
            st.markdown("""
            <div class="tech-panel">
                <h4>🕸️ Threat Graph</h4>
            </div>
            """, unsafe_allow_html=True)
            try:
                import networkx as nx
                G = graph.graph
                if G.number_of_nodes() > 0:
                    pos = nx.spring_layout(G, seed=42, k=0.9)
                    node_ids = list(G.nodes(data=True))
                    xs = [pos[nid][0] for nid, _ in node_ids]
                    ys = [pos[nid][1] for nid, _ in node_ids]
                    labels = [d.get("value", node_id) for node_id, d in node_ids]
                    type_colors = {"EMAIL": "#9333ea", "URL": "#00aaff",
                                   "DOMAIN": "#FFD700", "IP": "#FF4444"}
                    node_colors = [type_colors.get(d.get("node_type"), "#64748b") for _, d in node_ids]

                    fig_g = go.Figure()
                    for edge in G.edges():
                        u, v = edge[:2]
                        x0, y0 = pos[u]
                        x1, y1 = pos[v]
                        fig_g.add_trace(go.Scatter(
                            x=[x0, x1], y=[y0, y1], mode="lines",
                            line=dict(color="rgba(0,255,136,0.25)", width=1),
                            hoverinfo="none", showlegend=False,
                        ))
                    fig_g.add_trace(go.Scatter(
                        x=xs, y=ys, mode="markers+text",
                        text=labels,
                        textposition="top center",
                        textfont=dict(size=9, color="#c8d6e5", family="Share Tech Mono"),
                        marker=dict(
                            size=22, color=node_colors,
                            line=dict(width=1, color="rgba(255,255,255,0.25)"),
                            opacity=0.9,
                        ),
                        hovertext=[f"{nid}<br>Type: {d.get('node_type')}<br>Risk: {d.get('risk_level') or 'N/A'}"
                                   for nid, d in node_ids],
                        hoverinfo="text", showlegend=False,
                    ))
                    fig_g.update_layout(
                        paper_bgcolor="rgba(10,15,30,0.8)",
                        plot_bgcolor="rgba(10,15,30,0.0)",
                        margin=dict(l=10, r=10, t=10, b=10), height=420,
                        xaxis=dict(showgrid=False, zeroline=False, visible=False),
                        yaxis=dict(showgrid=False, zeroline=False, visible=False),
                        font=dict(family="Share Tech Mono"),
                    )
                    st.plotly_chart(fig_g, use_container_width=True, config={"displayModeBar": False})
                    gsum = graph.summary()
                    st.markdown(
                        f"<div style='color:#64748b; font-size:0.75rem; font-family:'Share Tech Mono', monospace;'>"
                        f"Nodes: EMAIL {gsum['by_type']['EMAIL']} · URL {gsum['by_type']['URL']} · "
                        f"DOMAIN {gsum['by_type']['DOMAIN']} · IP {gsum['by_type']['IP']} | "
                        f"Edges: contains {gsum['relations']['contains']} · belongs_to {gsum['relations']['belongs_to']} · "
                        f"resolves_to {gsum['relations']['resolves_to']} · received_from {gsum['relations']['received_from']}"
                        f"</div>", unsafe_allow_html=True)
            except Exception as e:
                st.warning(f"Threat graph rendering skipped: {e}")

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Forensic explanations (all suspicious IPs) ──
            if result["explanations"]:
                st.markdown("""
                <div class="tech-panel">
                    <h4>🔎 Forensic Explanations</h4>
                </div>
                """, unsafe_allow_html=True)
                for explain in result["explanations"]:
                    st.markdown(f"""
                    <div class="finding-item" style="border-left-color: #FF4444;">
                        <span style="color:#c8d6e5;">{explain}</span>
                    </div>
                    """, unsafe_allow_html=True)
                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            # ── Geoposition availability summary ──
            geo_failed = sum(1 for r in result["ip_results"]
                             if r["is_public"] and not (r.get("geo") or {}).get("ok"))
            if geo_failed:
                st.markdown("""
                <div class="tech-panel">
                    <h4>🌐 Geolocation Availability</h4>
                </div>
                """, unsafe_allow_html=True)
                st.warning(
                    f"Geolocation unavailable for {geo_failed} public IP(s). "
                    "This does not affect IP validation, classification or risk analysis.")

            # ── Tips ──
            st.markdown("""
            <div class="tech-panel">
                <h4>💡 IP Intelligence Recommendations</h4>
            </div>
            """, unsafe_allow_html=True)
            if risk_level == "high":
                ip_tips = [
                    ("🔴 HIGH RISK", "Public IPs carry suspicious signals. Correlate with SPF/DKIM/DMARC and domain intelligence."),
                    ("🎭 HOSTING/PROXY", "Hosting or proxy space can mask true origin — treat geo as probable context only."),
                    ("📋 DOCUMENT", "Save headers and IP evidence under the email_id for incident response."),
                ]
            elif risk_level == "moderate":
                ip_tips = [
                    ("🟠 MODERATE", "Several IP indicators are elevated. Cross-check with header forensics and URL analysis."),
                    ("🔍 VERIFY", "Confirm whether the infrastructure belongs to the claimed sender organization."),
                ]
            else:
                ip_tips = [
                    ("✅ LOW", "No significant IP-based red flags detected."),
                    ("🛡️ CORRELATE", "Clean IPs do not guarantee legitimacy — always combine with other stages."),
                ]
            ip_tip_cols = st.columns(len(ip_tips))
            for i, (title, desc) in enumerate(ip_tips):
                with ip_tip_cols[i]:
                    st.markdown(f"""
                    <div class="tip-card">
                        <div class="tip-title">{title}</div>
                        {desc}
                    </div>
                    """, unsafe_allow_html=True)


# ─── Origin & Cases tab ──────────────────────────────────────────────────────

with cases_tab:
    if not _HAS_NEW_MODULES:
        st.info("New modules (storage/header-trust) unavailable in this environment.")
    else:
        st.markdown("""
        <div class="tech-panel">
            <h4>🕸️ Origin, Cases & Evidence</h4>
            <p style="color: #64748b; font-size: 0.85rem; margin: 0; font-family: 'Share Tech Mono', monospace;">
                Stored analyses from the real-time ingest service → campaign grouping → tamper-evident audit log
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # Ingest config status
        ti_cfg = get_threat_intel_config()
        if ti_cfg["enabled"]:
            st.success(f"🛰️ {ti_cfg['message']}")
        else:
            st.info(f"ℹ️ {ti_cfg['message']}")

        # Usage guidance
        st.code(
            "# Start the real-time ingest listener (in another terminal)\n"
            "python -m ingest.webhook_server\n\n"
            "# Send an email for analysis\n"
            "curl -X POST http://localhost:8080/analyze \\\n"
            "     -H 'Content-Type: application/json' \\\n"
            "     -d '{\"text\": \"From: ...\\nSubject: ...\\n\\n...\"}'\n"
            "\n# For an .eml file:\n"
            "curl -X POST http://localhost:8080/analyze --data-binary @email.eml",
            language="shell", )

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        try:
            store = CaseStore()
            stats = store.stats()
            c1, c2, c3 = st.columns(3)
            for col, (label, value, color) in zip(
                (c1, c2, c3),
                [("Stored Emails", stats["emails"], "#00aaff"),
                 ("Campaigns", stats["campaigns"], "#FFD700"),
                 ("High/Critical Risk", stats["high_risk"], "#FF4444")]):
                with col:
                    st.markdown(f"""
                    <div class="metric-box">
                        <div class="metric-value" style="color: {color};">{value}</div>
                        <div class="metric-label">{label}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            cams = store.get_campaigns()
            if cams:
                st.markdown("""
                <div class="tech-panel">
                    <h4>🔁 Campaign Groups</h4>
                </div>
                """, unsafe_allow_html=True)
                cam_rows = [{
                    "Campaign": c["campaign_id"],
                    "Emails": c["email_count"],
                    "Verdicts": (c["verdicts"] or "").replace(",", ", "),
                    "Last Seen": c["last_seen"],
                } for c in cams]
                st.dataframe(pd.DataFrame(cam_rows), use_container_width=True, hide_index=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            emails = store.list_emails(limit=25)
            if emails:
                st.markdown("""
                <div class="tech-panel">
                    <h4>📥 Recent Stored Analyses</h4>
                </div>
                """, unsafe_allow_html=True)
                email_rows = [{
                    "Email ID": e["email_id"],
                    "From": e["from_email"],
                    "Subject": (e["subject"] or "")[:60],
                    "Class": e["verdict_class"],
                    "Priority": e["verdict_priority"],
                    "Score": e["combined_score"],
                    "IP Risk": e["ip_risk"],
                    "Stored": e["stored_at"],
                } for e in emails]
                st.dataframe(pd.DataFrame(email_rows), use_container_width=True, hide_index=True)

            # Chain-of-custody verification
            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
            coc = ChainOfCustodyLogger()
            v = coc.verify()
            if v["intact"]:
                st.success(f"🔐 Chain of custody intact — {v['entries']} signed audit entries verified.")
            else:
                st.error(f"⚠️ Chain of custody BROKEN — {len(v['issues'])} tampered entries detected.")
            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            recent_coc = coc.entries(limit=8)
            if recent_coc:
                st.markdown("""
                <div class="tech-panel">
                    <h4>🧾 Recent Audit Log</h4>
                </div>
                """, unsafe_allow_html=True)
                for en in recent_coc:
                    st.markdown(f"""
                    <div class="finding-item">
                        <span style="color:#64748b; font-size:0.8rem;">[{en['ts']}] {en['actor']}:</span>
                        <span style="color:#c8d6e5;">{en['event']} — {en['detail']}</span>
                    </div>
                    """, unsafe_allow_html=True)
        except Exception as e:
            st.warning(f"Case store unavailable: {e}")

# ─── Live Authentication & Active Tracking ───────────────────────────────────

with auth_tab:
    if not _HAS_NEW_MODULES:
        st.info("🔑 Live authentication & tracking module unavailable.")
    else:
        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("### 🔐 Live Authentication (SPF / DKIM / DMARC)")
            st.caption("Re-verifies email authentication against DNS instead of "
                       "trusting the receiver's Authentication-Results header. "
                       "Uses the earliest reliable public IP as the connecting client.")
            auth_file = st.file_uploader(
                "Or upload a .eml/.txt file for live authentication verification",
                type=["eml", "txt"],
                help="Upload an email file to evaluate live SPF, DKIM, and DMARC alignment",
                key="auth_file_uploader",
            )
            if auth_file is not None:
                a_bytes = auth_file.read()
                a_text = a_bytes.decode("utf-8", errors="ignore")
                a_parsed = parse_eml_file(a_bytes)
                st.session_state["raw_eml_bytes"] = a_bytes
                st.session_state["raw_eml_text"] = a_text
                st.session_state["parsed_eml"] = a_parsed
                st.session_state["auth_raw"] = a_text
                st.session_state["forensic_email"] = a_text
                st.session_state["forensic_email_textarea"] = a_text
                st.session_state["full_forensic_textarea"] = a_text
                st.session_state["ip_intel_textarea"] = a_text
                st.session_state["ip_intel_email"] = a_text
                st.info(f"📄 .EML File loaded for authentication: **{auth_file.name}**")

            if "auth_raw" not in st.session_state and st.session_state.get("raw_eml_text"):
                st.session_state["auth_raw"] = st.session_state.get("raw_eml_text")

            auth_raw = st.text_area(
                "Raw email (headers optional)",
                height=180, key="auth_raw",
                placeholder="From: \"Microsoft\" <security@example.com>\nReturn-Path: b@attacker.net\nReceived: from ...\n\nbody")
            if st.button("Verify authentication live", type="primary",
                         key="auth_verify_btn"):
                with st.spinner("Checking DNS (SPF, DKIM-Signature, _dmarc record)..."):
                    bytes_input = st.session_state.get("raw_eml_bytes") if st.session_state.get("raw_eml_text") == auth_raw else None
                    auth = authenticate_email(raw=auth_raw, bytes_raw=bytes_input)
                if auth["overall"] == "pass":
                    st.success("✅ **Overall: PASS** — authentication-conformant email")
                elif auth["overall"] == "fail":
                    st.error("🚨 **Overall: FAIL** — does not authenticate against its claimed domain")
                else:
                    st.warning("🟡 **Overall: UNVERIFIED** — cannot conclusively authenticate")
                for f in auth["findings"]:
                    st.markdown(f)
                st.markdown("---")
                k1, k2, k3 = st.columns(3)
                spf = auth["spf"]; dkim = auth["dkim"]; dmarc = auth["dmarc"]
                k1.metric("SPF", (spf.get("result") or spf.get("unavailable", "n/a")),
                          help=spf.get("explanation") or spf.get("unavailable"))
                k2.metric("DKIM", "verified" if dkim.get("verified") is True
                          else ("FAIL" if dkim.get("verified") is False
                                else dkim.get("unavailable", "n/a")),
                          help=(auth["dmarc"].get("explanation", "") or ""))
                k3.metric("DMARC", dmarc.get("outcome") or dmarc.get("unavailable", "n/a"),
                          help=dmarc.get("explanation") or "")
                st.caption(f"Evaluated for From-domain **{auth['from_domain'] or '(none)'}** "
                           f"· envelope **{auth['envelope_domain'] or '(none)'}** "
                           f"· earliest reliable IP **{auth['client_ip'] or '(none)'}**")
        with c2:
            st.markdown("### 🎯 Active Tracking Lures")
            st.caption("Mint an interaction token, embed the pixel/link in an "
                       "outbound (honeypot) email. When the recipient opens or "
                       "clicks it, their real IP + UA + referer are enriched "
                       "(geo-IP, RDAP registry, reverse DNS) in real time.")
            tr_email = st.text_input("Email ID for this lure", key="tr_email",
                                     placeholder="sha256:... or case email id")
            tr_target = st.text_input("Click-target URL (optional)", key="tr_target",
                                      placeholder="https://attacker.example/confirm")
            if st.button("Mint tracking token", key="tr_mint"):
                try:
                    tok = mint_email_token(str(tr_email), "")
                    st.success(f"Token minted: `{tok}`")
                    st.code(embed_html(tok, str(tr_target)), language="html")
                    st.caption("Serve via: `python -m tracking.server` "
                               "(TRACKING_BASE_URL controls the host in these links).")
                except Exception as e:
                    st.warning(f"Could not mint token: {e}")
            st.markdown("---")
            st.markdown("#### 📡 Observed interactions")
            try:
                events = TrackerStore().hits()
                if events:
                    rows = [{
                        "Token": e["token"][:8],
                        "Kind": e["kind"],
                        "IP": e["ip"],
                        "UA": (e["user_agent"] or "")[:40],
                        "Reverse": ((json.loads(e["enrichment"]).get("reverse") or "")
                                    if e.get("enrichment") else ""),
                        "At": e["created_at"],
                    } for e in events]
                    st.dataframe(pd.DataFrame(rows), use_container_width=True,
                                 hide_index=True)
                else:
                    st.caption("No interaction events yet — mint a token and place it "
                               "in an email body first.")
            except Exception as e:
                st.caption(f"Tracking store unavailable: {e}")
