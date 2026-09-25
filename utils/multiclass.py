"""
utils/multiclass.py - Five-class email threat classification.

Maps the spec's outcome classes onto the existing evidence pipeline:

    legitimate | suspicious | impersonated | phishing | fraud

Instead of a separate model file (the current ML binary model predicts
safe/phishing), this classifier fuses the already-extracted signals:

  * rule score + ML probability      (utils/__init__.py)
  * social-engineering attack type  (analyze_social_engineering)
  * header forensic signals         (forensic_engine)
  * origin/IP intelligence          (services/ip_analyzer)
  * lookalike domain analysis       (utils/lookalike)

Stays explainable - every class comes with human-readable reasons.
"""

from .lookalike import lookalike_risk


VERSION_CLASSES = ("legitimate", "suspicious", "impersonated", "phishing", "fraud")

# Social-engineering attack ids that map directly to BEC / financial fraud.
_BEC_ATTACK_IDS = {"ceo_fraud", "invoice_fraud", "quid_pro_quo"}

# Social-engineering attack ids that indicate impersonation of a person/brand.
_IMPERSONATION_ATTACK_IDS = {"pretexting", "spear_phishing", "tech_support_scam",
                             "romance_scam"}

# Confidence thresholds (combined 0..100) for the non-clean classes.
_THRESHOLDS = {
    "phishing_low": 45,
    "impersonation_low": 40,
    "fraud_low": 40,
    "phishing_high": 62,
    "fraud_high": 60,
}


def _parse_from_header(forensic) -> str:
    """Return a canonical from-address from forensic_data if present."""
    if not forensic:
        return ""
    data = forensic.get("forensic_data") or {}
    return str(data.get("from_email") or "").strip()


def _parse_sender_domain(forensic) -> str:
    if not forensic:
        return ""
    data = forensic.get("forensic_data") or {}
    return str(data.get("sender_domain") or "").strip()


def classify_email(rule_score=0, ml_result=None, soceng=None, forensic=None,
                   ip_summary=None, urls=None, from_email=None,
                   threat_intel_flags=None) -> dict:
    """
    Produce a five-class verdict from available evidence. All inputs optional;
    missing signals simply carry less weight.

    Args (all optional):
        rule_score        - 0..100 from rule_based_check
        ml_result         - dict from ml_predict (label, confidence)
        soceng            - dict from analyze_social_engineering
        forensic          - dict from forensic_engine.generate_forensic_report
                            (or any dict with 'findings'/'forensic_data')
        ip_summary        - dict with 'risk_level'/'max_score' (ip_analyzer summary)
        urls              - list of URLs found in the email
        from_email        - sender address (if forensic is unavailable)
        threat_intel_flags- list of extra signal strings

    Returns:
        {
          "class", "priority", "confidence", "reasons", "drivers",
          "from_email", "sender_domain"
        }
    """
    reasons = []
    drivers = []

    # ── 1. Base risk from rule + ML ──
    combined = float(rule_score or 0.0)
    if ml_result and not ml_result.get("error"):
        ml_label = ml_result.get("label")
        ml_conf = float(ml_result.get("confidence") or 0.0)
        if ml_label == "phishing":
            combined = 0.7 * combined + 0.6 * ml_conf * 100
        else:
            combined = 0.7 * combined + 0.4 * (1 - ml_conf) * 100
        drivers.append(f"ML model: {ml_label} (conf {round(ml_conf * 100)}%)")
    else:
        drivers.append("ML model unavailable - rule evidence weighted alone")

    # ── 2. Social-engineering layer ──
    primary_attack = None
    soceng_risk = 0
    if soceng:
        pa = soceng.get("primary_attack") or {}
        primary_attack = pa.get("id")
        soceng_risk = int(soceng.get("overall_risk") or 0)
        if pa:
            drivers.append(f"SE: {pa.get('name')} (conf {pa.get('confidence')}%)")

    # ── 3. Forensic signals (SPF/DKIM/DMARC, spoofing) ──
    spoofing_flag = False
    auth_fail_count = 0
    if forensic:
        findings = forensic.get("findings") or []
        for f in findings:
            low = str(f).lower()
            if "spoofing" in low or "impersonation" in low:
                spoofing_flag = True
            if "fail" in low and ("spf" in low or "dkim" in low or "dmarc" in low):
                auth_fail_count += 1
        drivers.append(f"Forensic: {auth_fail_count} auth failure(s), "
                       f"spoofing={'yes' if spoofing_flag else 'no'}")

    # ── 4. IP / origin layer ──
    if ip_summary:
        lvl = (ip_summary.get("risk_level") or "low")
        drivers.append(f"IP: {lvl} ({ip_summary.get('max_score', 0)}%)")
    for flag in (threat_intel_flags or []):
        reasons.append(f"Threat intel: {flag}")

    # ── 5. Lookalike domain scan ──
    lookalike_hits = []
    for url in (urls or []):
        host = str(url).lower()
        host = host.split("://")[-1].split("/")[0]
        rr = lookalike_risk(host)
        if rr["is_lookalike"]:
            lookalike_hits.append(rr)
    if lookalike_hits:
        brands = ", ".join(sorted({h["matched_brand"] for h in lookalike_hits}))
        reasons.append(f"Lookalike domain(s) resembling {brands}")

    # sender identity
    if not from_email:
        from_email = _parse_from_header(forensic)
    sender_domain = _parse_sender_domain(forensic)
    if sender_domain and lookalike_hits:
        reasons.append(f"Sender domain {sender_domain} detected as lookalike")

    # ── 6. Decision logic ──
    klass = "legitimate"
    priority = "normal"
    confidence = 0

    fraud_signal = primary_attack in _BEC_ATTACK_IDS and soceng_risk >= 25
    impersonation_signal = (primary_attack in _IMPERSONATION_ATTACK_IDS or
                            spoofing_flag or bool(lookalike_hits))
    phishing_signal = (primary_attack in ("phishing",) or
                       combined >= _THRESHOLDS["phishing_low"])

    if fraud_signal or (primary_attack in _BEC_ATTACK_IDS and combined >= 35):
        klass = "fraud"
        priority = "critical"
        confidence = max(soceng_risk, int(combined))
        reasons.append(f"BEC/financial-fraud pattern: "
                       f"{soceng.get('primary_attack', {}).get('name') if soceng and soceng.get('primary_attack') else primary_attack}")
    elif impersonation_signal and combined >= _THRESHOLDS["impersonation_low"]:
        klass = "impersonated"
        priority = "high" if combined >= 55 else "medium"
        confidence = max(soceng_risk, int(combined))
        if spoofing_flag:
            reasons.append("Display-name / sender spoofing detected in headers")
    elif phishing_signal:
        klass = "phishing"
        priority = "high"
        confidence = int(combined)
        reasons.append(f"Phishing indicators (combined score {int(combined)}%)")
        if lookalike_hits:
            reasons.append("Credential-harvest lookalike link present")
    elif combined >= 25:
        klass = "suspicious"
        priority = "medium"
        confidence = int(combined)
        reasons.append(f"Elevated signals but no decisive attack pattern ({int(combined)}%)")
    else:
        klass = "legitimate"
        priority = "normal"
        confidence = max(0, 100 - int(combined))
        reasons.append(f"No decisive indicators (combined score {int(combined)}%)")

    confidence = min(confidence, 100)

    return {
        "class": klass,
        "priority": priority,
        "confidence": confidence,
        "reasons": reasons[:6],
        "drivers": drivers,
        "from_email": from_email,
        "sender_domain": sender_domain,
    }