"""Pipeline part 1: parse + live URL/IP enrichment (cached, deduped, capped)."""
from __future__ import annotations

from .ai_analyzer import ai_verdict
from .cache import DOMAIN_CACHE, GEO_CACHE, HASH_CACHE, IP_CACHE, URL_CACHE
from .cache import norm_domain, norm_ip, norm_url
from .geolocation import geolocate
from .geo_providers import is_routable_public_ip
from .heuristics import domain_of
from .threat_intel import (abuseipdb_check, safe_browsing_check,
                           virustotal_domain, virustotal_hash,
                           virustotal_ip, virustotal_url)
from .url_analysis import analyze_url_local


MAX_URLS = 15
MAX_IPS = 15
MAX_DOMAINS = 15


def rep_live(verdict: str, available: bool) -> str:
    if not available:
        return "UNKNOWN"
    return {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS",
            "clean": "CLEAN", "unknown": "UNKNOWN"}.get(verdict, "UNKNOWN")


def risk_of(rep: str, abuse: int = 0) -> str:
    if rep == "MALICIOUS" or abuse >= 75:
        return "CRITICAL"
    if rep == "SUSPICIOUS" or abuse >= 25:
        return "HIGH"
    if rep == "UNKNOWN":
        return "MEDIUM"
    return "LOW"


async def enrich_urls(parsed: dict, settings):
    urls = list(dict.fromkeys(parsed.get("urls", [])))[:MAX_URLS]
    sb = await safe_browsing_check(urls[:10],
                                   settings.GOOGLE_SAFE_BROWSING_API_KEY,
                                   settings.EXTERNAL_TIMEOUT_S)
    flagged = set(sb.get("flagged", [])) if sb.get("available") else set()
    sb_available = bool(sb.get("available"))
    out, vt_mal = [], 0
    for u in urls:
        key = "url:" + norm_url(u)
        cached = URL_CACHE.get(key)
        if cached is not None:
            out.append(dict(cached))
            if cached.get("reputation") == "MALICIOUS":
                vt_mal += 1
            continue
        local = analyze_url_local(u)
        vt = await virustotal_url(u, settings.VIRUSTOTAL_API_KEY,
                                  settings.EXTERNAL_TIMEOUT_S)
        vrep = rep_live(vt.get("verdict", "unknown"),
                        vt.get("available", False))
        if u in flagged:
            vrep = "MALICIOUS"
        if vrep == "MALICIOUS":
            vt_mal += 1
        dom = domain_of(u)
        notes = list(local.get("indicators", []))
        if vt.get("available"):
            notes.append(f"VirusTotal: {vt.get('malicious', 0)} malicious / "
                         f"{vt.get('suspicious', 0)} suspicious")
        elif settings.VIRUSTOTAL_API_KEY:
            notes.append("VirusTotal lookup unavailable (timeout/error).")
        else:
            notes.append("VirusTotal not configured — reputation UNKNOWN.")
        if u in flagged:
            notes.append("Google Safe Browsing: flagged")
        elif sb_available:
            notes.append("Google Safe Browsing: not flagged")
        elif settings.GOOGLE_SAFE_BROWSING_API_KEY:
            notes.append("Safe Browsing lookup unavailable.")
        else:
            notes.append("Safe Browsing not configured — UNKNOWN.")
        if vrep == "UNKNOWN":
            notes.append("Unknown is NOT clean — treat as unverified.")
        row = {"url": u, "domain": dom,
               "https": u.lower().startswith("https://"),
               "redirect": dom in ("bit.ly", "tinyurl.com", "t.co"),
               "reputation": vrep, "risk": risk_of(vrep),
               "notes": notes[:8],
               "normalized": local.get("normalized", u),
               "providers": {"virustotal": vt, "safe_browsing_flagged": u in flagged,
                             "safe_browsing_available": sb_available}}
        URL_CACHE.set(key, row, ttl_s=6 * 3600)
        out.append(row)
    return out, vt_mal, len(flagged)


async def enrich_ips(parsed: dict, settings):
    ips = [i for i in list(dict.fromkeys(parsed.get("ips", [])))
           if is_routable_public_ip(i)][:MAX_IPS]
    ip_intel, geos, max_abuse = [], [], 0
    for ip in ips:
        key = "ip:" + norm_ip(ip)
        cached = IP_CACHE.get(key)
        if cached is not None:
            ip_intel.append(dict(cached["intel"]))
            geos.append(dict(cached["geo"]))
            max_abuse = max(max_abuse, int(cached["intel"].get("abuseScore", 0)))
            continue
        ab = await abuseipdb_check(ip, settings.ABUSEIPDB_API_KEY,
                                   settings.EXTERNAL_TIMEOUT_S)
        vt = await virustotal_ip(ip, settings.VIRUSTOTAL_API_KEY,
                                 settings.EXTERNAL_TIMEOUT_S)
        score = int(ab.get("abuse_score", 0)) if ab.get("available") else 0
        max_abuse = max(max_abuse, score)
        arep = rep_live(ab.get("verdict", "unknown"), ab.get("available", False))
        vtrep = rep_live(vt.get("verdict", "unknown"), vt.get("available", False))
        # Worst-of aggregation, but UNKNOWN never shown as clean.
        order = {"MALICIOUS": 3, "SUSPICIOUS": 2, "UNKNOWN": 1, "CLEAN": 0}
        rep = arep if order.get(arep, 1) >= order.get(vtrep, 1) else vtrep
        gkey = "geo:" + norm_ip(ip)
        geo = GEO_CACHE.get(gkey)
        if geo is None:
            geo = await geolocate(ip, settings.EXTERNAL_TIMEOUT_S)
            GEO_CACHE.set(gkey, geo, ttl_s=24 * 3600)
        else:
            geo = dict(geo)
        geos.append({**geo, "ip": ip})
        row = {"ip": ip, "reputation": rep, "country": geo.get("country", "UNKNOWN"),
               "countryCode": geo.get("countryCode", "--"),
               "city": geo.get("city", "UNKNOWN"),
               "region": geo.get("region", "UNKNOWN"),
               "isp": geo.get("isp", "UNKNOWN"), "asn": geo.get("asn", "UNKNOWN"),
               "abuseScore": score, "risk": risk_of(rep, score),
               "lat": geo.get("lat", 0.0), "lon": geo.get("lon", 0.0),
               "geo": geo,
               "providers": {"abuseipdb": ab, "virustotal": vt}}
        IP_CACHE.set(key, {"intel": row, "geo": {**geo, "ip": ip}}, ttl_s=6 * 3600)
        ip_intel.append(row)
    return ip_intel, geos, max_abuse
