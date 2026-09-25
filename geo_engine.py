"""
geo_engine.py - Geolocation Intelligence Engine
Resolves domains to IP addresses, performs IP geolocation,
and provides geographic threat intelligence.
"""

import os
import socket
import re
import time
from urllib.parse import urlparse
import plotly.graph_objects as go
from utils import normalize_url_or_domain
from services.geoip_service import GeoIPService

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ─── Known High-Risk Countries (by threat actor volume) ───────────────────────

HIGH_RISK_COUNTRIES = {
    "Russia": {"risk": "high", "color": "#FF4444", "notes": "Major source of cyber threat actors"},
    "China": {"risk": "high", "color": "#FF6B35", "notes": "State-sponsored APT activity"},
    "North Korea": {"risk": "critical", "color": "#FF0000", "notes": "Lazarus Group, financial theft operations"},
    "Iran": {"risk": "high", "color": "#FF4444", "notes": "State-sponsored operations, APT groups"},
    "Brazil": {"risk": "moderate", "color": "#FFA500", "notes": "Financial fraud and banking trojans"},
    "India": {"risk": "low", "color": "#FFD700", "notes": "Call center scams, tech support fraud"},
    "Nigeria": {"risk": "high", "color": "#FF6B35", "notes": "419 scams, BEC operations, romance scams"},
    "Vietnam": {"risk": "moderate", "color": "#FFA500", "notes": "Emerging threat actor region"},
    "Indonesia": {"risk": "low", "color": "#FFD700", "notes": "Phishing infrastructure hosting"},
    "Ukraine": {"risk": "moderate", "color": "#FFA500", "notes": "Hacktivism, cyber warfare"},
    "Singapore": {"risk": "low", "color": "#FFD700", "notes": "Phishing infrastructure relay"},
    "Hong Kong": {"risk": "moderate", "color": "#FFA500", "notes": "APC infrastructure proxy"},
}

# Known CDN/proxy providers (these mask true origin)
KNOWN_CDNS = {
    "cloudflare": {"provider": "Cloudflare", "trusted": True},
    "akamai": {"provider": "Akamai", "trusted": True},
    "amazonaws": {"provider": "Amazon AWS", "trusted": True},
    "fastly": {"provider": "Fastly", "trusted": True},
    "google": {"provider": "Google Cloud", "trusted": True},
    "microsoft": {"provider": "Microsoft Azure", "trusted": True},
    "incapsula": {"provider": "Incapsula/Imperva", "trusted": True},
}


# ─── DNS Resolution ───────────────────────────────────────────────────────────

def resolve_dns(domain: str) -> dict:
    """
    Perform comprehensive DNS resolution for a domain or URL.
    Normalizes inputs (strips scheme, path, query, port) before DNS lookup.
    """
    norm = normalize_url_or_domain(domain)
    target_domain = norm["hostname"] or domain.strip()

    results = {
        "domain": target_domain,
        "raw_input": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname_records": [],
        "errors": [],
    }

    if not target_domain:
        results["errors"].append("Empty or invalid domain name provided")
        return results

    # If input is already an IP address, return it directly
    if norm.get("is_ip"):
        results["a_records"] = [target_domain]
        return results


    if not HAS_DNS:
        # Fallback to socket
        try:
            ips = socket.getaddrinfo(domain, None)
            a_records = list(set(addr[4][0] for addr in ips if addr[0] == socket.AF_INET))
            results["a_records"] = a_records
        except Exception as e:
            results["errors"].append(f"DNS resolution failed: {str(e)}")
        return results

    # A Records
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        results["a_records"] = [str(r) for r in answers]
    except Exception as e:
        results["errors"].append(f"A record lookup failed: {str(e)}")

    # AAAA Records
    try:
        answers = dns.resolver.resolve(domain, "AAAA", lifetime=5)
        results["aaaa_records"] = [str(r) for r in answers]
    except Exception:
        pass

    # MX Records
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        results["mx_records"] = [{"priority": r.preference, "exchange": str(r.exchange).rstrip(".")} for r in answers]
    except Exception:
        pass

    # NS Records
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        results["ns_records"] = [str(r).rstrip(".") for r in answers]
    except Exception:
        pass

    # TXT Records
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        results["txt_records"] = [str(r).strip('"') for r in answers]
    except Exception:
        pass

    # CNAME Records
    try:
        answers = dns.resolver.resolve(domain, "CNAME", lifetime=5)
        results["cname_records"] = [str(r).rstrip(".") for r in answers]
    except Exception:
        pass

    return results


def get_reverse_dns(ip: str) -> str:
    """Perform reverse DNS lookup for an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except Exception:
        return "N/A"


# ─── IP Geolocation ───────────────────────────────────────────────────────────

def geolocate_ip(ip: str) -> dict:
    """
    Look up geographic information for an IP address using GeoIPService / ip-api.com.
    Returns country, city, ISP, coordinates, and threat intelligence.
    """
    result = {
        "ip": ip,
        "country": None,
        "country_code": None,
        "city": None,
        "region": None,
        "latitude": None,
        "longitude": None,
        "isp": None,
        "org": None,
        "as_info": None,
        "timezone": None,
        "is_proxy": False,
        "threat_level": "unknown",
        "threat_notes": [],
        "error": None,
    }

    # Try GeoIPService first
    try:
        service = GeoIPService()
        res = service.lookup_ip(ip)
        if res.get("ok"):
            result["country"] = res.get("country")
            result["country_code"] = res.get("country_code")
            result["city"] = res.get("city")
            result["region"] = res.get("region")
            result["latitude"] = res.get("latitude")
            result["longitude"] = res.get("longitude")
            result["isp"] = res.get("isp")
            result["org"] = res.get("organization")
            result["as_info"] = res.get("asn")
            result["timezone"] = res.get("timezone")
            result["is_proxy"] = bool(res.get("hosting"))

            country = res.get("country") or ""
            if country in HIGH_RISK_COUNTRIES:
                risk_info = HIGH_RISK_COUNTRIES[country]
                result["threat_level"] = risk_info["risk"]
                result["threat_notes"].append(risk_info["notes"])
            else:
                result["threat_level"] = "low"

            if result["is_proxy"]:
                result["threat_notes"].append("IP belongs to a proxy/VPN/hosting provider")
                if result["threat_level"] == "low":
                    result["threat_level"] = "moderate"
            return result
    except Exception:
        pass

    # Fallback to direct ip-api.com HTTP request
    if not HAS_REQUESTS:
        result["error"] = "requests library not installed"
        return result

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,timezone,proxy,hosting"},
            timeout=10,
        )
        data = response.json()

        if data.get("status") == "success":
            result["country"] = data.get("country")
            result["country_code"] = data.get("countryCode")
            result["city"] = data.get("city")
            result["region"] = data.get("regionName")
            result["latitude"] = data.get("lat")
            result["longitude"] = data.get("lon")
            result["isp"] = data.get("isp")
            result["org"] = data.get("org")
            result["as_info"] = data.get("as")
            result["timezone"] = data.get("timezone")
            result["is_proxy"] = data.get("proxy", False) or data.get("hosting", False)

            country = data.get("country", "")
            if country in HIGH_RISK_COUNTRIES:
                risk_info = HIGH_RISK_COUNTRIES[country]
                result["threat_level"] = risk_info["risk"]
                result["threat_notes"].append(risk_info["notes"])
            else:
                result["threat_level"] = "low"

            if result["is_proxy"]:
                result["threat_notes"].append("IP belongs to a proxy/VPN/hosting provider")
                if result["threat_level"] == "low":
                    result["threat_level"] = "moderate"
        else:
            result["error"] = data.get("message", "Geolocation failed")
    except Exception as e:
        result["error"] = str(e)

    return result


def geolocate_domain(domain: str) -> dict:
    """
    Full domain geolocation pipeline: DNS resolve → geolocate all IPs.
    Accepts arbitrary URLs or domains and normalizes them cleanly.
    """
    dns_data = resolve_dns(domain)
    clean_domain = dns_data["domain"]
    ips = dns_data["a_records"]

    geo_results = []
    for ip in ips[:5]:  # Limit to 5 IPs
        geo = geolocate_ip(ip)
        geo["reverse_dns"] = get_reverse_dns(ip)
        geo_results.append(geo)

    # Check for CDN/proxy detection
    cdn_detected = []
    for record in geo_results:
        if record.get("is_proxy"):
            cdn_detected.append(record.get("isp", "Unknown"))

    # Determine overall threat
    threat_levels = {"critical": 4, "high": 3, "moderate": 2, "low": 1, "unknown": 0}
    max_threat = max(geo_results, key=lambda x: threat_levels.get(x["threat_level"], 0)) if geo_results else None

    return {
        "domain": clean_domain,
        "raw_input": domain,
        "dns": dns_data,
        "ip_count": len(ips),
        "geolocations": geo_results,
        "cdn_detected": cdn_detected,
        "overall_threat": max_threat["threat_level"] if max_threat else "unknown",
        "all_threat_notes": [note for geo in geo_results for note in geo.get("threat_notes", [])],
    }



# ─── Map Data Generation ──────────────────────────────────────────────────────

def generate_map_data(domain: str, geo_result: dict) -> list:
    """
    Generate data points for Plotly map visualization.
    Returns a list of dicts with lat, lon, label, color.
    """
    points = []
    threat_colors = {
        "critical": "#FF0000",
        "high": "#FF4444",
        "moderate": "#FFA500",
        "low": "#00ff88",
        "unknown": "#64748b",
    }

    for geo in geo_result.get("geolocations", []):
        if geo.get("latitude") and geo.get("longitude"):
            points.append({
                "ip": geo["ip"],
                "lat": geo["latitude"],
                "lon": geo["longitude"],
                "city": geo.get("city", "Unknown"),
                "country": geo.get("country", "Unknown"),
                "isp": geo.get("isp", "Unknown"),
                "threat": geo.get("threat_level", "unknown"),
                "color": threat_colors.get(geo.get("threat_level", "unknown"), "#64748b"),
                "is_proxy": geo.get("is_proxy", False),
            })

    return points


def build_geolocation_map_figure(map_points: list, height: int = 400) -> go.Figure:
    """
    Build a Plotly map figure rendering real GeoIP coordinates on a realistic satellite imagery layer.
    Supports MAPBOX_TOKEN / MAPBOX_STYLE from .env if provided, open Esri World Imagery satellite raster tiles,
    and graceful fallback to Scattergeo vector map if satellite tile rendering fails.
    """
    fig = go.Figure()
    if not map_points:
        fig.update_layout(
            paper_bgcolor="rgba(10,15,30,0.8)",
            plot_bgcolor="rgba(10,15,30,0.0)",
            height=height,
        )
        return fig

    valid_points = [p for p in map_points if p.get("lat") is not None and p.get("lon") is not None]
    if not valid_points:
        fig.update_layout(
            paper_bgcolor="rgba(10,15,30,0.8)",
            plot_bgcolor="rgba(10,15,30,0.0)",
            height=height,
        )
        return fig

    lats = [p["lat"] for p in valid_points]
    lons = [p["lon"] for p in valid_points]

    hover_texts = [
        f"<b>{p.get('ip', 'IP')}</b><br>"
        f"{p.get('city', 'Unknown')}, {p.get('country', 'Unknown')}<br>"
        f"ISP: {p.get('isp', 'Unknown')}<br>"
        f"Threat: {str(p.get('threat', p.get('risk_level', 'unknown'))).upper()}"
        f"{'<br>⚠️ Proxy/VPN' if p.get('is_proxy') else ''}"
        for p in valid_points
    ]

    colors = [p.get("color", "#64748b") for p in valid_points]
    sizes = [16 if p.get("threat") in ("high", "critical") or p.get("risk_level") in ("high", "critical", "moderate") else 11 for p in valid_points]

    center_lat = sum(lats) / len(lats)
    center_lon = sum(lons) / len(lons)

    mapbox_token = os.getenv("MAPBOX_TOKEN", "").strip()
    mapbox_style = os.getenv("MAPBOX_STYLE", "satellite-streets").strip()

    # Determine Scattermap class supported by installed Plotly version
    scatter_cls = getattr(go, "Scattermap", None) or getattr(go, "Scattermapbox", None)
    map_layout_key = "map" if hasattr(go, "Scattermap") else "mapbox"

    if scatter_cls:
        try:
            fig.add_trace(scatter_cls(
                lat=lats,
                lon=lons,
                mode="markers+text",
                marker=dict(
                    size=sizes,
                    color=colors,
                    opacity=0.9,
                ),
                text=[p.get("ip", "") for p in valid_points],
                textposition="top center",
                hoverinfo="text",
                hovertext=hover_texts,
            ))

            map_config = dict(
                center=dict(lat=center_lat, lon=center_lon),
                zoom=2 if len(lats) > 1 else 4,
            )

            if mapbox_token:
                map_config["accesstoken"] = mapbox_token
                map_config["style"] = mapbox_style
            else:
                map_config["style"] = "white-bg"
                map_config["layers"] = [{
                    "below": "traces",
                    "sourcetype": "raster",
                    "source": ["https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"]
                }]

            layout_args = {
                map_layout_key: map_config,
                "paper_bgcolor": "rgba(10,15,30,0.8)",
                "plot_bgcolor": "rgba(10,15,30,0.0)",
                "margin": dict(l=0, r=0, t=10, b=10),
                "height": height,
                "font": dict(family="Share Tech Mono"),
                "showlegend": False,
            }
            fig.update_layout(**layout_args)
            return fig
        except Exception:
            fig = go.Figure()  # Fall back to Scattergeo if satellite tile layout fails

    # Graceful Fallback: High-contrast dark vector Scattergeo map
    fig.add_trace(go.Scattergeo(
        lon=lons,
        lat=lats,
        text=hover_texts,
        hoverinfo="text",
        marker=dict(
            size=sizes,
            color=colors,
            line=dict(width=2, color="rgba(255,255,255,0.4)"),
            opacity=0.9,
        ),
        name="IP Locations",
    ))

    fig.update_layout(
        geo=dict(
            showframe=False,
            showcoastlines=True,
            coastlinecolor="rgba(0,255,136,0.3)",
            projection_type="natural earth",
            bgcolor="rgba(10,15,30,0.0)",
            landcolor="rgba(15,23,42,0.9)",
            showland=True,
            showcountries=True,
            countrycolor="rgba(0,255,136,0.15)",
            showocean=True,
            oceancolor="rgba(5,5,16,0.9)",
            showlakes=True,
            lakecolor="rgba(5,5,16,0.9)",
        ),
        paper_bgcolor="rgba(10,15,30,0.8)",
        plot_bgcolor="rgba(10,15,30,0.0)",
        margin=dict(l=0, r=0, t=10, b=10),
        height=height,
        font=dict(family="Share Tech Mono"),
        showlegend=False,
    )
    return fig


# ─── Threat Assessment Summary ────────────────────────────────────────────────

def assess_geo_threat(geo_result: dict) -> dict:
    """
    Generate a summary threat assessment based on geolocation intelligence.
    """
    findings = []
    score = 0
    notes = []

    # Check for high-risk countries
    threat_notes = geo_result.get("all_threat_notes", [])
    high_risk_count = sum(1 for n in threat_notes if any(
        hr in n for hr in ["threat actor", "APT", "financial theft", "BEC", "419"]
    ))
    if high_risk_count > 0:
        score += 30
        findings.append(f"🔴 IP(s) located in high-risk threat actor regions")
        notes.extend([n for n in threat_notes if "threat" in n.lower() or "apt" in n.lower()])

    # Check for proxy/VPN usage
    proxy_count = sum(1 for geo in geo_result.get("geolocations", []) if geo.get("is_proxy"))
    if proxy_count > 0:
        score += 20
        findings.append(f"🟠 {proxy_count} IP(s) belong to proxy/VPN/hosting providers (true origin masked)")
        notes.append("Proxy/VPN detected — geographic origin may be obscured")

    # Check DNS resolution issues
    dns_data = geo_result.get("dns", {})
    if dns_data.get("errors"):
        score += 10
        findings.append(f"🟡 DNS resolution warnings: {'; '.join(dns_data['errors'][:2])}")

    # Check for multiple geographically diverse IPs (possible CDN or infrastructure)
    countries = set(geo.get("country") for geo in geo_result.get("geolocations", []) if geo.get("country"))
    if len(countries) > 2:
        score += 10
        findings.append(f"🟡 IPs distributed across {len(countries)} countries: {', '.join(countries)}")

    # Check for no MX records (suspicious for domain sending email)
    if not dns_data.get("mx_records") and not dns_data.get("a_records"):
        score += 15
        findings.append("🟠 No MX records found — domain may not be configured for email")
        notes.append("Missing email infrastructure suggests possible impersonation")

    # Check for lack of DNS records
    total_records = (
        len(dns_data.get("a_records", [])) +
        len(dns_data.get("mx_records", [])) +
        len(dns_data.get("ns_records", []))
    )
    if total_records == 0:
        score += 25
        findings.append("🔴 No DNS records found — domain may not exist or be freshly registered")
        notes.append("Domain has minimal infrastructure — high risk of being a throwaway domain")

    # Cap score
    score = min(score, 100)

    # Determine threat level
    if score >= 60:
        threat_level = "high"
        threat_emoji = "🔴"
        threat_text = "High Geographic Risk"
        threat_color = "#FF4444"
    elif score >= 30:
        threat_level = "moderate"
        threat_emoji = "🟠"
        threat_text = "Moderate Geographic Risk"
        threat_color = "#FFA500"
    elif score > 0:
        threat_level = "low"
        threat_emoji = "🟡"
        threat_text = "Low Geographic Risk"
        threat_color = "#FFD700"
    else:
        threat_level = "safe"
        threat_emoji = "✅"
        threat_text = "Geographically Safe"
        threat_color = "#00ff88"

    if not findings:
        findings.append("✅ No geographic red flags detected")

    return {
        "score": score,
        "threat_level": threat_level,
        "threat_emoji": threat_emoji,
        "threat_text": threat_text,
        "threat_color": threat_color,
        "findings": findings,
        "notes": notes,
    }
