"""URL analysis: safe normalization + indicator extraction (no fetching)."""
from __future__ import annotations

from urllib.parse import urlparse, unquote
import re


def normalize_url(u: str) -> str:
    u = (u or "").strip().rstrip(".,;)")
    if len(u) > 2000:
        u = u[:2000]
    return u


def analyze_url_local(url: str) -> dict:
    norm = normalize_url(url)
    try:
        p = urlparse(norm)
    except Exception:
        return {"url": url, "normalized": norm, "hostname": "",
                "indicators": ["Unparseable URL."], "risk_hint": "unknown"}
    host = (p.hostname or "").lower()
    indicators: list[str] = []
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        indicators.append("IP-literal host (evades domain reputation).")
    if "xn--" in host:
        indicators.append("Punycode host (possible homograph).")
    if "%" in norm and ("%" + "2" in norm.upper() or "%3" in norm.upper()):
        indicators.append("Suspicious percent-encoding.")
    if "@" in norm.split("?", 1)[0] and not norm.lower().startswith("mailto:"):
        indicators.append("Credential-looking '@' in URL authority/path.")
    if host in ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd"):
        indicators.append("URL shortener — final destination hidden.")
    try:
        if unquote(norm) != norm and ("@" in unquote(norm) or "://" in unquote(norm)):
            indicators.append("Double-encoded redirect pattern.")
    except Exception:
        pass
    if p.port and p.port not in (80, 443):
        indicators.append(f"Non-standard port :{p.port}.")
    if len(p.query or "") > 0:
        indicators.append("Query string present (tracking/exfil possible).")
    if p.path and len(p.path) > 120:
        indicators.append("Unusually long path.")
    return {"url": url, "normalized": norm, "scheme": p.scheme or "",
            "hostname": host, "port": p.port,
            "has_query": bool(p.query), "path_len": len(p.path or ""),
            "indicators": indicators,
            "risk_hint": "suspicious" if indicators else "unknown"}
