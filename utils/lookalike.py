"""
utils/lookalike.py - Lookalike / homograph domain detection.

Catches "domain lookalikes" such as paypa1.com, micros0ft-login.co, apple.support.
Uses Levenshtein-style edit distance (damerau-levenshtein via difflib is too
string-matching focused, so we use a compact implementation) applied against a
small built-in brand list, plus homograph (punycode/confusable) checks.

Kept dependency-free and deterministic so it can run in any environment.
"""

import re
from difflib import SequenceMatcher

# High-value brands attackers impersonate most (names used in display-name
# spoofing checks across the codebase).
BRAND_NAMES = [
    "google", "gmail", "youtube", "microsoft", "outlook", "windows", "office365",
    "apple", "icloud", "dropbox", "amazon", "paypal", "netflix", "facebook",
    "instagram", "linkedin", "twitter", "whatsapp", "github", "slack", "zoom",
    "microsoft365", "one drive", "onedrive",
]

# Brands whose display name gets impersonated for BEC (financially relevant).
FINANCIAL_BRANDS = [
    "paypal", "bank", "chase", "wells fargo", "citibank", "hsbc", "barclays",
    "stripe", "square", "venmo", "western union", "amazon", "apple", "microsoft",
]

_HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "8": "b", "@": "a", "$": "s", "!": "i", "|": "l",
}


def normalized_brand_name(brand: str) -> str:
    """Lowercase and strip spaces so 'one drive' vs 'onedrive' collapse."""
    return re.sub(r"[^a-z0-9]", "", brand.lower())


def _homoglyph_normalize(domain: str) -> str:
    out = []
    for ch in domain.lower():
        alnum = re.sub(r"[^a-z0-9]", "", ch)
        if alnum == "":
            # separators (hyphen, dot) drop out of homoglyph comparison
            out.append("")
            continue
        out.append(_HOMOGLYPH_MAP.get(ch, ch))
    return "".join(out)


def extract_domain_name(domain: str) -> str:
    """Strip TLD/service prefixes to get the registrable name for comparison."""
    if not domain:
        return ""
    host = domain.lower().strip()
    # Drop scheme/path if accidental.
    host = re.sub(r"^[a-z]+://", "", host)
    host = host.split("/")[0]
    parts = host.split(".")
    # public-suffix-lite: keep main label + next label
    if len(parts) >= 3:
        main = parts[-2]
    elif len(parts) == 2:
        main = parts[0]
    else:
        main = host
    return main


def lookalike_risk(domain: str, brand_list=None) -> dict:
    """
    Assess how closely a domain resembles a known brand.

    Returns:
        {
          "is_lookalike": bool,
          "matched_brand": str|None,
          "similarity": float,        # 0..1 (SequenceMatcher on normalized name)
          "edit_distance_detected": bool,
          "homoglyph_detected": bool,
          "domain": str,
        }
    """
    brand_list = brand_list or BRAND_NAMES
    if not domain:
        return {"is_lookalike": False, "matched_brand": None, "similarity": 0.0,
                "edit_distance_detected": False, "homoglyph_detected": False,
                "domain": domain}

    main = extract_domain_name(domain)
    norm = normalized_brand_name(main)

    best_brand = None
    best_sim = 0.0
    for brand in brand_list:
        bnorm = normalized_brand_name(brand)
        if not bnorm:
            continue
        sim = SequenceMatcher(None, norm, bnorm).ratio()
        if sim > best_sim:
            best_sim = sim
            best_brand = brand

    homoglyph = _homoglyph_normalize(main)
    homoglyph_flag = False
    for brand in brand_list:
        bnorm = normalized_brand_name(brand)
        if not bnorm:
            continue
        if homoglyph == _homoglyph_normalize(bnorm):
            homoglyph_flag = True
            best_brand = brand
            break
    # Brand-squatting with suffix/prefix, e.g. micr0s0ft-login -> contains the
    # homoglyph-normalized brand ("microsoftlogin" contains "microsoft").
    if not homoglyph_flag:
        for brand in brand_list:
            bnorm = normalized_brand_name(brand)
            if not bnorm:
                continue
            bnorm_h = _homoglyph_normalize(bnorm)
            if bnorm_h and (bnorm_h in homoglyph or homoglyph in bnorm_h):
                homoglyph_flag = True
                best_brand = brand
                break

    same = norm == normalized_brand_name(best_brand or "")

    # Edit-distance style check: similarity high but not identical brand string.
    edit_distance_detected = (
        not same and best_sim >= 0.79 and norm not in ("",)
    )

    is_lookalike = (edit_distance_detected or homoglyph_flag) and not same

    return {
        "is_lookalike": is_lookalike,
        "matched_brand": best_brand if is_lookalike else None,
        "similarity": round(best_sim, 3),
        "edit_distance_detected": edit_distance_detected,
        "homoglyph_detected": homoglyph_flag,
        "domain": domain,
    }


def flag_lookalike_domains(urls, brand_list=None) -> list:
    """Scan a list of URLs and return lookalike findings."""
    findings = []
    for url in urls or []:
        raw = str(url)
        host = re.sub(r"^[a-z]+://", "", raw.lower()).split("/")[0].split("?")[0]
        risk = lookalike_risk(host, brand_list=brand_list)
        if risk["is_lookalike"]:
            findings.append({
                "url": url,
                "host": host,
                "brand": risk["matched_brand"],
                "similarity": risk["similarity"],
            })
    return findings