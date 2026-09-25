"""
utils.py - Core Phishing Detection Engine
Combines rule-based analysis with ML predictions for robust email classification.
"""

import re
import warnings
from urllib.parse import urlparse
import joblib

def normalize_url_or_domain(input_str: str) -> dict:
    """
    Safely normalize arbitrary user input (URL, domain, IP, host:port, path, query).
    Returns clean hostname for DNS/GeoIP lookups along with URL component metadata.
    """
    raw = (input_str or "").strip()
    if not raw:
        return {"raw": "", "hostname": "", "scheme": "", "port": None, "path": "", "query": "", "is_ip": False}

    # Add scheme if missing so urlparse works predictably
    parse_target = raw
    if not parse_target.startswith(("http://", "https://", "ftp://", "data:", "javascript:")):
        parse_target = "http://" + parse_target

    try:
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").strip().lower()
        # Remove trailing dot if present
        if hostname.endswith("."):
            hostname = hostname[:-1]

        # Handle raw domain with path/query passed without scheme (urlparse puts hostname in path if no scheme)
        if not hostname:
            parts = raw.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip().lower()
            hostname = parts

        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)) or bool(re.match(r"^[0-9a-fA-F:]+$", hostname) and ":" in hostname)
        return {
            "raw": raw,
            "hostname": hostname,
            "scheme": parsed.scheme if raw.startswith(("http://", "https://", "ftp://")) else "",
            "port": parsed.port,
            "path": parsed.path or "",
            "query": parsed.query or "",
            "is_ip": is_ip,
        }
    except Exception:
        # Fallback regex extraction
        clean = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
        clean = clean.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip().lower()
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean))
        return {"raw": raw, "hostname": clean, "scheme": "", "port": None, "path": "", "query": "", "is_ip": is_ip}


# ─── Phishing Indicators ──────────────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "urgent", "immediately", "click here", "verify your", "confirm your",
    "account suspended", "account compromised", "act now", "limited time",
    "free gift", "you have won", "congratulations", "claim your",
    "bank details", "credit card", "social security", "password expired",
    "unauthorized access", "security alert", "security breach", "data leak",
    "final warning", "final notice", "last chance", "immediate action",
    "account will be", "permanently", "within 24 hours", "within 48 hours",
    "failure to", "risk losing", "do not ignore", "update your payment",
    "billing error", "past due", "pay now", "processing fee",
    "lottery", "inheritance", "selected as winner", "specially selected",
    "call immediately", "do not turn off", "virus detected", "infected",
]

URGENCY_PHRASES = [
    "act now", "immediate", "urgent", "hurry", "limited time",
    "expires today", "within 24 hours", "within 48 hours",
    "don't delay", "right away", "asap", "last chance",
    "final warning", "final notice", "before it's too late",
]

SUSPICIOUS_TLD_PATTERNS = [
    r"\.tk\b", r"\.xyz\b", r"\.ru\b", r"\.cn\b",
    r"\.top\b", r"\.buzz\b", r"\.gq\b", r"\.ml\b",
    r"\.cf\b", r"\.ga\b",
]


# ─── Text Preprocessing ──────────────────────────────────────────────────────

def preprocess_text(text: str) -> str:
    """Clean and normalize email text for analysis."""
    if not text:
        return ""
    # Convert to lowercase
    text = text.lower()
    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)
    # Remove URLs but keep them for separate analysis (lowercase token so the
    # [^a-z0-9\s] filter below cannot strip it)
    text = re.sub(r"http\S+|www\.\S+", " url ", text)
    # Remove email addresses
    text = re.sub(r"\S+@\S+", " email ", text)
    # Remove special characters but keep spaces
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    # Collapse multiple spaces
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ─── Feature Extraction ──────────────────────────────────────────────────────

def extract_urls(text: str) -> list:
    """Extract all URLs from the email text."""
    url_pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+|[a-zA-Z0-9.-]+\.(?:tk|xyz|ru|cn|com|org|net)/[^\s]*"
    matches = re.findall(url_pattern, text, re.IGNORECASE)
    return [u.rstrip(".,;:!?)") for u in matches]


def extract_email_features(text: str) -> dict:
    """Extract detailed features from email text for display."""
    text_lower = text.lower()

    # Find matched phishing keywords
    matched_keywords = []
    for keyword in PHISHING_KEYWORDS:
        if keyword in text_lower:
            matched_keywords.append(keyword)

    # Find urgency phrases
    matched_urgency = []
    for phrase in URGENCY_PHRASES:
        if phrase in text_lower:
            matched_urgency.append(phrase)

    # Extract URLs
    urls = extract_urls(text)

    # Check for suspicious TLDs
    suspicious_urls = []
    for url in urls:
        for pattern in SUSPICIOUS_TLD_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_urls.append(url)
                break

    # Check for ALL CAPS words (shouting)
    caps_words = re.findall(r"\b[A-Z]{3,}\b", text)
    caps_words = [w for w in caps_words if w not in ("URL", "HTTP", "HTTPS", "HTML", "CEO", "PTO", "HR", "PM", "AM", "RSVP")]

    # Check for money/financial references
    money_refs = re.findall(r"\$[\d,]+\.?\d*", text)

    return {
        "phishing_keywords": matched_keywords,
        "urgency_phrases": matched_urgency,
        "urls_found": urls,
        "suspicious_urls": suspicious_urls,
        "caps_words": caps_words,
        "money_references": money_refs,
        "has_urgency": len(matched_urgency) > 0,
        "has_suspicious_links": len(suspicious_urls) > 0,
        "keyword_count": len(matched_keywords),
    }


# ─── Rule-Based Detection ────────────────────────────────────────────────────

def rule_based_check(text: str) -> dict:
    """
    Perform rule-based phishing analysis.
    Returns a score (0-100) and detailed findings.
    """
    features = extract_email_features(text)
    score = 0
    findings = []

    # Keyword scoring (max 40 points)
    keyword_count = features["keyword_count"]
    if keyword_count >= 5:
        score += 40
        findings.append(f"🔴 High number of phishing keywords detected ({keyword_count})")
    elif keyword_count >= 3:
        score += 25
        findings.append(f"🟠 Multiple phishing keywords detected ({keyword_count})")
    elif keyword_count >= 1:
        score += 10
        findings.append(f"🟡 Some phishing keywords detected ({keyword_count})")

    # Suspicious URLs (max 30 points)
    if features["has_suspicious_links"]:
        score += 30
        findings.append(f"🔴 Suspicious URLs with risky TLDs: {', '.join(features['suspicious_urls'][:3])}")
    elif len(features["urls_found"]) > 0:
        score += 5
        findings.append(f"🟡 Contains {len(features['urls_found'])} URL(s)")

    # Urgency scoring (max 15 points)
    if features["has_urgency"]:
        urgency_count = len(features["urgency_phrases"])
        if urgency_count >= 3:
            score += 15
            findings.append(f"🔴 High urgency language ({urgency_count} phrases)")
        else:
            score += 8
            findings.append(f"🟠 Urgency language detected ({urgency_count} phrases)")

    # ALL CAPS shouting (max 10 points)
    if len(features["caps_words"]) >= 3:
        score += 10
        findings.append(f"🟠 Excessive CAPS usage: {', '.join(features['caps_words'][:5])}")
    elif len(features["caps_words"]) >= 1:
        score += 3
        findings.append(f"🟡 Some CAPS words: {', '.join(features['caps_words'][:3])}")

    # Money references (max 5 points)
    if features["money_references"]:
        score += 5
        findings.append(f"🟡 Financial amounts mentioned: {', '.join(features['money_references'][:3])}")

    # Cap the score at 100
    score = min(score, 100)

    if not findings:
        findings.append("✅ No suspicious patterns detected by rule-based analysis")

    return {
        "score": score,
        "findings": findings,
        "features": features,
    }


# ─── ML-Based Detection ──────────────────────────────────────────────────────

def load_model(model_path: str = "model.pkl", vectorizer_path: str = "vectorizer.pkl"):
    """Load the trained ML model and TF-IDF vectorizer safely suppressing unpickle version warnings."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model = joblib.load(model_path)
            vectorizer = joblib.load(vectorizer_path)
            return model, vectorizer
    except (FileNotFoundError, Exception):
        return None, None



def ml_predict(text: str, model, vectorizer) -> dict:
    """
    Make a prediction using the trained ML model.
    Returns prediction label and confidence score.
    """
    if model is None or vectorizer is None:
        return {"label": "unknown", "confidence": 0.0, "error": "Model not loaded"}

    # Preprocess
    clean_text = preprocess_text(text)

    # Vectorize
    text_vector = vectorizer.transform([clean_text])

    # Predict
    prediction = model.predict(text_vector)[0]
    probabilities = model.predict_proba(text_vector)[0]

    # Get confidence
    confidence = float(max(probabilities))

    return {
        "label": prediction,
        "confidence": confidence,
        "probabilities": {
            label: float(prob)
            for label, prob in zip(model.classes_, probabilities)
        },
    }


# ─── Combined Analysis ───────────────────────────────────────────────────────

def combine_results(rule_result: dict, ml_result: dict) -> dict:
    """
    Combine rule-based and ML results into a final verdict.
    Rule-based weight: 40%, ML weight: 60%
    """
    rule_score = rule_result["score"]  # 0-100

    # Convert ML result to a 0-100 score
    if ml_result.get("label") == "unknown" and ml_result.get("error"):
        # If ML model isn't available, use only rule-based
        ml_score = 0
        rule_weight = 1.0
        ml_weight = 0.0
    else:
        # Phishing-likelihood from class probabilities. Binary model exposes
        # 'safe'/'phishing'; a 5-class model exposes 'legitimate'+ classified
        # threats - both reduce to "probability of not benign".
        proba = ml_result.get("probabilities") or {}
        p_phish = proba.get("phishing")
        if p_phish is None:
            benign = proba.get("safe", proba.get("legitimate", 0.0))
            p_phish = max(0.0, 1.0 - benign)
        ml_score = float(p_phish) * 100
        rule_weight = 0.4
        ml_weight = 0.6

    # Combined score
    combined_score = (rule_score * rule_weight) + (ml_score * ml_weight)

    # Determine verdict
    if combined_score >= 60:
        verdict = "phishing"
        verdict_emoji = "🚨"
        verdict_text = "Phishing Email Detected!"
        verdict_color = "#FF4444"
    elif combined_score >= 35:
        verdict = "suspicious"
        verdict_emoji = "⚠️"
        verdict_text = "Suspicious Email"
        verdict_color = "#FFA500"
    else:
        verdict = "safe"
        verdict_emoji = "✅"
        verdict_text = "Safe Email"
        verdict_color = "#44BB44"

    return {
        "verdict": verdict,
        "verdict_emoji": verdict_emoji,
        "verdict_text": verdict_text,
        "verdict_color": verdict_color,
        "combined_score": round(combined_score, 1),
        "rule_score": rule_score,
        "ml_score": round(ml_score, 1) if not ml_result.get("error") else None,
        "rule_weight": rule_weight,
        "ml_weight": ml_weight,
        "rule_findings": rule_result["findings"],
        "ml_prediction": ml_result,
        "features": rule_result.get("features", {}),
    }


def analyze_email(text: str, model=None, vectorizer=None) -> dict:
    """
    Full analysis pipeline: Rule-based + ML → Combined verdict.
    """
    # Rule-based analysis
    rule_result = rule_based_check(text)

    # ML prediction
    if model is not None and vectorizer is not None:
        ml_result = ml_predict(text, model, vectorizer)
    else:
        ml_result = {"label": "unknown", "confidence": 0.0, "error": "Model not loaded"}

    # Combine
    result = combine_results(rule_result, ml_result)
    return result


# ─── URL Phishing Detection ──────────────────────────────────────────────────

SUSPICIOUS_TLDS = [
    ".tk", ".xyz", ".ru", ".cn", ".top", ".buzz", ".gq", ".ml",
    ".cf", ".ga", ".work", ".click", ".link", ".info", ".biz",
    ".cc", ".pw", ".su", ".review", ".zip", ".mov",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
]

PHISHING_DOMAIN_KEYWORDS = [
    "secure", "login", "verify", "account", "update", "banking",
    "signin", "confirm", "auth", "wallet", "paypal", "apple",
    "microsoft", "google", "amazon", "facebook", "netflix",
    "support", "service", "recover", "suspend", "alert",
]


def extract_url_features(url: str) -> dict:
    """Extract suspicious features from a URL for phishing analysis."""
    url_lower = url.lower().strip()

    # Normalise: add scheme if missing so parsing works
    parse_url = url_lower
    if not parse_url.startswith(("http://", "https://", "ftp://")):
        parse_url = "http://" + parse_url

    # ── Parse components ──
    from urllib.parse import urlparse
    parsed = urlparse(parse_url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_url = parse_url

    # 1. IP address instead of domain
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))

    # 2. HTTPS check
    uses_https = url_lower.startswith("https://")

    # 3. Suspicious TLD
    suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    matched_tld = next((tld for tld in SUSPICIOUS_TLDS if hostname.endswith(tld)), None)

    # 4. Subdomain depth
    subdomain_parts = hostname.split(".")
    subdomain_count = max(0, len(subdomain_parts) - 2)  # e.g. a.b.example.com → 2

    # 5. Hyphens in domain
    # Strip TLD portion for hyphen check
    domain_body = ".".join(subdomain_parts[:-1]) if len(subdomain_parts) > 1 else hostname
    hyphen_count = domain_body.count("-")

    # 6. URL length
    url_length = len(url_lower)

    # 7. Contains port number
    has_port = parsed.port is not None and parsed.port not in (80, 443)

    # 8. Contains @ symbol (credential trick)
    has_at_sign = "@" in url_lower

    # 9. Phishing keywords in domain
    matched_keywords = [kw for kw in PHISHING_DOMAIN_KEYWORDS if kw in hostname]

    # 10. URL shortener
    is_shortener = any(s in hostname for s in URL_SHORTENERS)

    # 11. Punycode / internationalized domain
    has_punycode = "xn--" in hostname

    # 12. Data URI / javascript scheme
    is_data_uri = url_lower.startswith("data:") or url_lower.startswith("javascript:")

    # 13. Path depth
    path_depth = len([p for p in path.split("/") if p])

    # 14. Suspicious file extensions in path
    suspicious_extensions = [".exe", ".scr", ".zip", ".php", ".cgi"]
    has_suspicious_ext = any(path.endswith(ext) for ext in suspicious_extensions)

    return {
        "is_ip": is_ip,
        "uses_https": uses_https,
        "suspicious_tld": suspicious_tld,
        "matched_tld": matched_tld,
        "subdomain_count": subdomain_count,
        "hyphen_count": hyphen_count,
        "url_length": url_length,
        "has_port": has_port,
        "has_at_sign": has_at_sign,
        "matched_keywords": matched_keywords,
        "is_shortener": is_shortener,
        "has_punycode": has_punycode,
        "is_data_uri": is_data_uri,
        "path_depth": path_depth,
        "has_suspicious_ext": has_suspicious_ext,
        "hostname": hostname,
        "path": path,
    }


def rule_based_url_check(url: str) -> dict:
    """
    Rule-based URL phishing analysis.
    Returns a score (0-100) and detailed findings.
    """
    features = extract_url_features(url)
    score = 0
    findings = []

    # IP address instead of domain (20 pts)
    if features["is_ip"]:
        score += 20
        findings.append(f"🔴 URL uses an IP address instead of a domain name ({features['hostname']})")

    # No HTTPS (10 pts)
    if not features["uses_https"]:
        score += 10
        findings.append("🟠 URL does not use HTTPS encryption")

    # Suspicious TLD (20 pts)
    if features["suspicious_tld"]:
        score += 20
        findings.append(f"🔴 Suspicious top-level domain: {features['matched_tld']}")

    # Excessive subdomains (15 pts)
    if features["subdomain_count"] >= 3:
        score += 15
        findings.append(f"🔴 Excessive subdomains detected ({features['subdomain_count']} levels deep)")
    elif features["subdomain_count"] >= 2:
        score += 7
        findings.append(f"🟠 Multiple subdomains detected ({features['subdomain_count']} levels)")

    # Hyphens in domain (10 pts)
    if features["hyphen_count"] >= 3:
        score += 10
        findings.append(f"🔴 Excessive hyphens in domain ({features['hyphen_count']})")
    elif features["hyphen_count"] >= 1:
        score += 5
        findings.append(f"🟡 Hyphens in domain name ({features['hyphen_count']})")

    # Very long URL (10 pts)
    if features["url_length"] > 100:
        score += 10
        findings.append(f"🟠 Unusually long URL ({features['url_length']} characters)")
    elif features["url_length"] > 75:
        score += 5
        findings.append(f"🟡 Long URL ({features['url_length']} characters)")

    # Non-standard port (10 pts)
    if features["has_port"]:
        score += 10
        findings.append("🟠 URL uses a non-standard port number")

    # @ sign trick (15 pts)
    if features["has_at_sign"]:
        score += 15
        findings.append("🔴 URL contains @ symbol — possible credential/redirect trick")

    # Phishing keywords in domain (15 pts)
    if len(features["matched_keywords"]) >= 3:
        score += 15
        findings.append(f"🔴 Multiple phishing keywords in domain: {', '.join(features['matched_keywords'][:5])}")
    elif len(features["matched_keywords"]) >= 1:
        score += 8
        findings.append(f"🟠 Phishing keywords in domain: {', '.join(features['matched_keywords'][:3])}")

    # URL shortener (10 pts)
    if features["is_shortener"]:
        score += 10
        findings.append("🟠 URL is a known URL shortener — destination hidden")

    # Punycode (10 pts)
    if features["has_punycode"]:
        score += 10
        findings.append("🔴 Punycode/internationalized domain — possible homograph attack")

    # Data URI or javascript (25 pts)
    if features["is_data_uri"]:
        score += 25
        findings.append("🔴 Data/JavaScript URI scheme — highly suspicious")

    # Suspicious file extension in path (10 pts)
    if features["has_suspicious_ext"]:
        score += 10
        findings.append("🟠 Suspicious file extension in URL path")

    score = min(score, 100)

    if not findings:
        findings.append("✅ No suspicious patterns detected in this URL")

    return {
        "score": score,
        "findings": findings,
        "features": features,
    }


def analyze_url(url: str) -> dict:
    """
    Full URL analysis pipeline (rule-based only).
    Returns a result dict compatible with the email analysis UI.
    """
    rule_result = rule_based_url_check(url)
    score = rule_result["score"]

    # Determine verdict using same thresholds as email
    if score >= 60:
        verdict = "phishing"
        verdict_emoji = "🚨"
        verdict_text = "Phishing URL Detected!"
        verdict_color = "#FF4444"
    elif score >= 35:
        verdict = "suspicious"
        verdict_emoji = "⚠️"
        verdict_text = "Suspicious URL"
        verdict_color = "#FFA500"
    else:
        verdict = "safe"
        verdict_emoji = "✅"
        verdict_text = "Safe URL"
        verdict_color = "#44BB44"

    return {
        "verdict": verdict,
        "verdict_emoji": verdict_emoji,
        "verdict_text": verdict_text,
        "verdict_color": verdict_color,
        "combined_score": score,
        "rule_score": score,
        "ml_score": None,
        "rule_weight": 1.0,
        "ml_weight": 0.0,
        "rule_findings": rule_result["findings"],
        "ml_prediction": {"label": "N/A", "confidence": 0.0, "error": "URL analysis uses rule-based detection only"},
        "features": rule_result["features"],
        "analysis_type": "url",
    }


# ─── Social Engineering Attack Detection ─────────────────────────────────────

# ── Attack Type Definitions ───────────────────────────────────────────────────

ATTACK_TYPES = {
    "phishing": {
        "name": "Phishing",
        "icon": "🎣",
        "color": "#FF4444",
        "description": "Mass-targeted attempt to steal credentials, personal data, or financial information by impersonating a trusted entity.",
        "how_it_works": "Attackers send emails or messages that appear to come from legitimate organizations (banks, tech companies, government agencies). They use fake login pages, urgent warnings, and deceptive links to trick victims into revealing sensitive information.",
        "defense": [
            "Never click links in unsolicited emails — navigate directly to the website",
            "Check the sender's full email address for misspellings",
            "Look for generic greetings like 'Dear Customer' instead of your name",
            "Enable multi-factor authentication on all accounts",
        ],
    },
    "spear_phishing": {
        "name": "Spear Phishing",
        "icon": "🎯",
        "color": "#FF6B35",
        "description": "Highly targeted attack using personal/organizational details to appear credible and bypass suspicion.",
        "how_it_works": "Unlike generic phishing, spear phishing targets specific individuals using researched personal details — your name, job title, recent activities, or colleagues' names. The attacker crafts a convincing pretext that feels personally relevant.",
        "defense": [
            "Be suspicious of emails referencing internal details that feel 'too specific'",
            "Verify requests through a separate communication channel",
            "Limit personal information shared on social media",
            "Report targeted emails to your security team immediately",
        ],
    },
    "pretexting": {
        "name": "Pretexting",
        "icon": "🎭",
        "color": "#9333EA",
        "description": "Fabricated scenario or false identity used to manipulate the victim into providing information or access.",
        "how_it_works": "The attacker invents a believable storyline — pretending to be IT support, HR, a vendor, or law enforcement — to build trust. They use this fabricated context to extract sensitive information or gain system access over time.",
        "defense": [
            "Always verify the identity of anyone requesting sensitive information",
            "Call back using official phone numbers, not ones provided in the message",
            "Be wary of unsolicited contacts claiming to be from internal departments",
            "Follow your organization's verification procedures",
        ],
    },
    "baiting": {
        "name": "Baiting",
        "icon": "🪤",
        "color": "#FFD700",
        "description": "Lures victims with enticing offers — free gifts, prizes, downloads — to steal information or install malware.",
        "how_it_works": "Attackers offer something appealing: free software, movie downloads, gift cards, prize winnings, or USB drives left in public places. The 'bait' contains malware or leads to credential-harvesting pages.",
        "defense": [
            "If an offer seems too good to be true, it almost certainly is",
            "Never plug in unknown USB drives or storage devices",
            "Download software only from official sources",
            "Be skeptical of unsolicited prize or lottery notifications",
        ],
    },
    "quid_pro_quo": {
        "name": "Quid Pro Quo",
        "icon": "🔄",
        "color": "#00CED1",
        "description": "Offers a service or benefit in exchange for information — 'I'll help you if you give me your login.'",
        "how_it_works": "The attacker poses as someone offering help — tech support fixing your computer, a researcher offering payment for a survey, or a service provider offering a free upgrade. In exchange, they request login credentials, remote access, or personal data.",
        "defense": [
            "Never give credentials to anyone offering unsolicited help",
            "Verify service requests through official channels",
            "Be cautious of 'free' services that require sensitive information",
            "Report unsolicited tech support calls to your IT department",
        ],
    },
    "ceo_fraud": {
        "name": "CEO Fraud / BEC",
        "icon": "👔",
        "color": "#FF1493",
        "description": "Impersonates executives or authority figures to authorize urgent wire transfers, data sharing, or policy exceptions.",
        "how_it_works": "Business Email Compromise (BEC) involves impersonating a CEO, CFO, or senior manager to pressure employees into making urgent wire transfers, sharing payroll data, or bypassing normal procedures. The 'executive' often claims to be traveling or in a meeting.",
        "defense": [
            "Verify any financial requests through a phone call to the executive",
            "Implement dual-authorization for wire transfers",
            "Be suspicious of requests that bypass normal approval processes",
            "Check the email address carefully — look for subtle misspellings",
        ],
    },
    "vishing_smishing": {
        "name": "Vishing / Smishing",
        "icon": "📱",
        "color": "#00BFFF",
        "description": "Voice calls (vishing) or SMS texts (smishing) used to extract information or direct victims to malicious sites.",
        "how_it_works": "Attackers use phone calls or text messages claiming to be from banks, government agencies, or tech companies. They create urgency ('Your account has been compromised!') and direct victims to fake websites or convince them to share information over the phone.",
        "defense": [
            "Never provide personal information in response to unsolicited calls/texts",
            "Hang up and call the organization directly using their official number",
            "Don't click links in unexpected text messages",
            "Register your number on do-not-call lists",
        ],
    },
    "tech_support_scam": {
        "name": "Tech Support Scam",
        "icon": "🖥️",
        "color": "#FF8C00",
        "description": "Fake alerts about viruses, compromised devices, or expiring licenses designed to gain remote access or payment.",
        "how_it_works": "Pop-ups, emails, or phone calls warn that your computer is infected or your license has expired. The 'tech support' team asks for remote access to 'fix' the issue, then installs malware, steals data, or demands payment for fake services.",
        "defense": [
            "Legitimate companies never send unsolicited tech support warnings",
            "Never grant remote access to unsolicited callers",
            "Close suspicious pop-ups using Task Manager, not by clicking them",
            "Use only authorized IT support channels",
        ],
    },
    "romance_scam": {
        "name": "Romance / Relationship Scam",
        "icon": "💕",
        "color": "#FF69B4",
        "description": "Builds emotional connection and trust over time, then exploits it for money, gifts, or personal information.",
        "how_it_works": "Scammers create fake profiles on dating sites or social media, build romantic relationships over weeks or months, then fabricate emergencies requiring money — medical bills, travel costs, or investment opportunities. They exploit emotional attachment.",
        "defense": [
            "Be cautious of online relationships that move unusually fast",
            "Never send money to someone you haven't met in person",
            "Reverse-image search profile photos to check for fakes",
            "Be wary of partners who always have excuses to avoid video calls",
        ],
    },
    "invoice_fraud": {
        "name": "Invoice / Payment Fraud",
        "icon": "📦",
        "color": "#32CD32",
        "description": "Fake invoices, payment redirection requests, or fraudulent billing designed to divert funds.",
        "how_it_works": "Attackers send fake invoices that look like they come from real vendors, or compromise a vendor's email to change payment details. They may also send 'updated banking information' notices to redirect legitimate payments to attacker-controlled accounts.",
        "defense": [
            "Verify any changes to payment details through a known phone number",
            "Implement invoice verification procedures with your finance team",
            "Cross-check invoice numbers and amounts with purchase orders",
            "Be suspicious of urgent requests to change banking information",
        ],
    },
}


# ── Per-Attack-Type Indicator Patterns ────────────────────────────────────────

ATTACK_INDICATORS = {
    "phishing": [
        "verify your account", "confirm your identity", "click here",
        "update your information", "your account has been", "suspended",
        "unauthorized access", "security alert", "dear customer",
        "dear user", "dear valued", "click the link below",
        "log in to your account", "reset your password", "unusual activity",
        "we noticed", "confirm your details", "validate your",
        "reactivate your", "account will be closed", "verify now",
    ],
    "spear_phishing": [
        "as discussed", "per our conversation", "following up on",
        "as per your request", "your employee id", "your department",
        "your manager", "mentioned your name", "recommended by",
        "your recent order", "your recent purchase", "regarding your application",
        "your project", "your team", "i was referred to you",
        "based on your profile", "we reviewed your", "in reference to",
        "your colleague", "we met at",
    ],
    "pretexting": [
        "i'm from it department", "this is from hr", "it support",
        "help desk", "we are conducting", "routine audit",
        "compliance check", "security review", "mandatory update",
        "policy change", "new procedure", "verification process",
        "internal investigation", "as part of our", "we require all employees",
        "company policy requires", "regulatory requirement", "due diligence",
        "background check", "access review",
    ],
    "baiting": [
        "free gift", "you have won", "congratulations", "claim your prize",
        "lottery", "sweepstakes", "selected as winner", "lucky winner",
        "free download", "free trial", "no cost", "completely free",
        "gift card", "reward", "bonus offer", "exclusive deal",
        "limited offer", "free iphone", "free vacation", "you've been chosen",
    ],
    "quid_pro_quo": [
        "in exchange for", "if you provide", "we can help you",
        "free technical support", "free security scan", "i'll fix",
        "let me help", "in return", "just need your password",
        "quick survey", "research study", "compensation for your time",
        "assist you with", "remote assistance", "we can resolve",
        "all i need is", "simple exchange", "mutual benefit",
    ],
    "ceo_fraud": [
        "wire transfer", "urgent transfer", "confidential matter",
        "do not discuss", "keep this between us", "i'm in a meeting",
        "i'm traveling", "cannot call right now", "handle this immediately",
        "i need you to", "process this today", "authorize payment",
        "executive request", "from the desk of", "on behalf of the ceo",
        "direct order", "board approved", "i'm the cfo", "i'm the ceo",
        "acting on behalf",
    ],
    "vishing_smishing": [
        "call this number", "call immediately", "call us back",
        "text back", "reply with", "send a text", "sms verification",
        "phone verification", "dial", "reach us at", "contact us at",
        "press 1", "press 2", "automated message", "robo call",
        "your package", "delivery notification", "shipment held",
        "tracking number",
    ],
    "tech_support_scam": [
        "virus detected", "malware found", "your computer is infected",
        "system compromised", "security breach detected",
        "windows has detected", "apple has detected", "microsoft alert",
        "license expired", "activation required", "remote access",
        "teamviewer", "anydesk", "allow remote", "tech support",
        "do not turn off", "do not restart", "call microsoft",
        "your ip has been", "firewall alert",
    ],
    "romance_scam": [
        "i love you", "fallen in love", "my dear", "my darling",
        "soul mate", "meant to be", "destiny brought us",
        "i need money for", "medical emergency", "stranded",
        "hospital bills", "travel to meet you", "customs fee",
        "i'm stuck", "help me financially", "western union",
        "money transfer", "can you send", "i promise to repay",
        "inheritance money",
    ],
    "invoice_fraud": [
        "invoice attached", "payment due", "outstanding balance",
        "overdue payment", "updated banking details", "new bank account",
        "wire instructions", "remittance", "payment required",
        "billing department", "accounts payable", "purchase order",
        "vendor payment", "change of bank", "revised invoice",
        "updated payment information", "ach transfer", "bank details changed",
        "process payment", "pay immediately",
    ],
}


# ── Psychological Tactic Indicators ──────────────────────────────────────────

PSYCHOLOGICAL_TACTICS = {
    "authority": {
        "name": "Authority",
        "icon": "👑",
        "color": "#FFD700",
        "description": "Impersonating officials, executives, or trusted institutions to command compliance.",
        "indicators": [
            "ceo", "cfo", "cto", "director", "manager", "administrator",
            "police", "fbi", "irs", "government", "federal", "court order",
            "legal action", "law enforcement", "official notice",
            "compliance officer", "security team", "it department",
            "hr department", "board of directors", "executive order",
            "regulatory body", "from the desk of", "authorized by",
        ],
    },
    "urgency": {
        "name": "Urgency / Scarcity",
        "icon": "⏰",
        "color": "#FF4444",
        "description": "Creating time pressure to force hasty decisions without verification.",
        "indicators": [
            "urgent", "immediately", "right now", "asap", "act now",
            "within 24 hours", "within 48 hours", "expires today",
            "last chance", "final warning", "final notice", "time sensitive",
            "limited time", "don't delay", "hurry", "deadline",
            "before it's too late", "running out", "only hours left",
            "must respond", "time is critical", "do not wait",
        ],
    },
    "fear": {
        "name": "Fear / Threat",
        "icon": "😨",
        "color": "#FF0000",
        "description": "Threatening negative consequences to manipulate through anxiety and panic.",
        "indicators": [
            "account suspended", "account closed", "permanently",
            "legal action", "criminal charges", "arrest warrant",
            "risk losing", "data breach", "compromised",
            "unauthorized access", "security breach", "identity theft",
            "failure to comply", "penalty", "fine", "prosecution",
            "terminate your", "revoke access", "ban your account",
            "report to authorities", "warrant issued",
        ],
    },
    "social_proof": {
        "name": "Social Proof",
        "icon": "👥",
        "color": "#00BFFF",
        "description": "Referencing others who have complied to create perceived normalcy.",
        "indicators": [
            "many users", "other employees", "everyone in your department",
            "your colleagues have", "most people", "thousands of customers",
            "other clients", "widely used", "trusted by millions",
            "recommended by", "endorsed by", "as others have done",
            "join thousands", "popular choice", "community approved",
        ],
    },
    "reciprocity": {
        "name": "Reciprocity",
        "icon": "🎁",
        "color": "#32CD32",
        "description": "Offering something first to create a sense of obligation.",
        "indicators": [
            "free gift", "complimentary", "no charge", "bonus",
            "as a token", "special offer", "exclusive access",
            "free trial", "we've already", "provided you with",
            "in appreciation", "thank you for being", "loyalty reward",
            "we've credited", "free upgrade", "courtesy of",
        ],
    },
    "familiarity": {
        "name": "Familiarity / Liking",
        "icon": "🤝",
        "color": "#FF69B4",
        "description": "Using personal details, warm tone, or shared connections to build false trust.",
        "indicators": [
            "hi [name]", "dear friend", "we've met", "as you know",
            "mutual friend", "your friend", "remember me",
            "it was great meeting", "we share", "common interest",
            "fellow", "like you", "people like us", "we're alike",
            "i understand how you feel", "i've been there too",
        ],
    },
}


# ── Social Engineering Analysis Engine ────────────────────────────────────────

def _score_indicators(text_lower: str, indicators: list) -> tuple:
    """Score text against a list of indicator phrases. Returns (score, matched)."""
    matched = []
    for indicator in indicators:
        if indicator in text_lower:
            matched.append(indicator)
    return len(matched), matched


def _extract_evidence(text: str, phrase: str, context_chars: int = 80) -> str:
    """Extract a snippet of text surrounding a matched phrase for evidence display."""
    text_lower = text.lower()
    idx = text_lower.find(phrase.lower())
    if idx == -1:
        return ""
    start = max(0, idx - context_chars // 2)
    end = min(len(text), idx + len(phrase) + context_chars // 2)
    snippet = text[start:end].replace("\n", " ").strip()
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet


def analyze_social_engineering(text: str) -> dict:
    """
    Analyze text for social engineering attack indicators.
    Returns classified attack types with confidence, psychological tactics, and evidence.
    """
    if not text or not text.strip():
        return {
            "primary_attack": None,
            "attack_scores": {},
            "tactics_detected": {},
            "overall_risk": 0,
            "risk_level": "none",
            "error": "No text provided",
        }

    text_lower = text.lower()

    # ── Score each attack type ──
    attack_scores = {}
    attack_evidence = {}
    max_possible_per_type = {}

    for attack_id, indicators in ATTACK_INDICATORS.items():
        score, matched = _score_indicators(text_lower, indicators)
        max_possible = len(indicators)
        max_possible_per_type[attack_id] = max_possible

        # Normalize to 0-100 with diminishing returns curve
        if max_possible > 0:
            raw_ratio = score / max_possible
            # Use a curve so even 30-40% keyword match gives high confidence
            confidence = min(100, raw_ratio * 250)  # 40% match → 100%
        else:
            confidence = 0

        attack_scores[attack_id] = round(confidence, 1)
        attack_evidence[attack_id] = [
            {"phrase": m, "snippet": _extract_evidence(text, m)}
            for m in matched[:5]  # Top 5 evidence items
        ]

    # ── Score psychological tactics ──
    tactics_detected = {}
    tactics_evidence = {}

    for tactic_id, tactic_info in PSYCHOLOGICAL_TACTICS.items():
        score, matched = _score_indicators(text_lower, tactic_info["indicators"])
        max_possible = len(tactic_info["indicators"])
        if max_possible > 0:
            confidence = min(100, (score / max_possible) * 250)
        else:
            confidence = 0

        if confidence > 0:
            tactics_detected[tactic_id] = {
                "name": tactic_info["name"],
                "icon": tactic_info["icon"],
                "color": tactic_info["color"],
                "description": tactic_info["description"],
                "confidence": round(confidence, 1),
                "matched_count": score,
            }
            tactics_evidence[tactic_id] = [
                {"phrase": m, "snippet": _extract_evidence(text, m)}
                for m in matched[:3]
            ]

    # ── Determine primary attack type ──
    sorted_attacks = sorted(attack_scores.items(), key=lambda x: x[1], reverse=True)
    primary_attack_id = sorted_attacks[0][0] if sorted_attacks and sorted_attacks[0][1] > 0 else None

    # ── Calculate overall risk score ──
    # Weighted combination of top attack score and tactic diversity
    top_attack_score = sorted_attacks[0][1] if sorted_attacks else 0
    tactic_count = len([t for t in tactics_detected.values() if t["confidence"] > 15])
    tactic_bonus = min(30, tactic_count * 8)  # Max 30 bonus points for tactic diversity

    overall_risk = min(100, round(top_attack_score * 0.7 + tactic_bonus, 1))

    # ── Determine risk level ──
    if overall_risk >= 70:
        risk_level = "critical"
        risk_emoji = "🚨"
        risk_text = "Critical Threat — Social Engineering Attack Detected"
        risk_color = "#FF4444"
    elif overall_risk >= 45:
        risk_level = "high"
        risk_emoji = "🔴"
        risk_text = "High Risk — Strong Social Engineering Indicators"
        risk_color = "#FF6B35"
    elif overall_risk >= 25:
        risk_level = "moderate"
        risk_emoji = "⚠️"
        risk_text = "Moderate Risk — Some Manipulation Tactics Present"
        risk_color = "#FFA500"
    elif overall_risk >= 10:
        risk_level = "low"
        risk_emoji = "🟡"
        risk_text = "Low Risk — Minor Indicators Detected"
        risk_color = "#FFD700"
    else:
        risk_level = "safe"
        risk_emoji = "✅"
        risk_text = "Safe — No Social Engineering Indicators Found"
        risk_color = "#00ff88"

    # ── Build result ──
    primary_info = None
    if primary_attack_id and attack_scores.get(primary_attack_id, 0) > 0:
        at = ATTACK_TYPES[primary_attack_id]
        primary_info = {
            "id": primary_attack_id,
            "name": at["name"],
            "icon": at["icon"],
            "color": at["color"],
            "confidence": attack_scores[primary_attack_id],
            "description": at["description"],
            "how_it_works": at["how_it_works"],
            "defense": at["defense"],
        }

    # Filter attack scores to only types with > 0 confidence, sorted descending
    ranked_attacks = [
        {
            "id": aid,
            "name": ATTACK_TYPES[aid]["name"],
            "icon": ATTACK_TYPES[aid]["icon"],
            "color": ATTACK_TYPES[aid]["color"],
            "confidence": score,
            "evidence": attack_evidence.get(aid, []),
        }
        for aid, score in sorted_attacks
        if score > 0
    ]

    return {
        "primary_attack": primary_info,
        "ranked_attacks": ranked_attacks,
        "attack_scores": dict(sorted_attacks),
        "tactics_detected": tactics_detected,
        "tactics_evidence": tactics_evidence,
        "overall_risk": overall_risk,
        "risk_level": risk_level,
        "risk_emoji": risk_emoji,
        "risk_text": risk_text,
        "risk_color": risk_color,
    }
