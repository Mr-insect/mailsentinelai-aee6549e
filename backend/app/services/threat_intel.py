"""LIVE threat-intel clients. Keys only from server env. Never log keys."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging

import httpx

log = logging.getLogger("mailsentinel.intel")


def _redact(msg: str) -> str:
    return msg  # callers must never interpolate keys into messages


async def virustotal_ip(ip: str, api_key: str, timeout: float) -> dict:
    """VirusTotal IP report. Never raises; honors provider status codes."""
    if not api_key:
        return {"available": False}
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"available": False}
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                            headers={"x-apikey": api_key})
        if r.status_code == 404:
            return {"available": True, "malicious": 0, "suspicious": 0, "verdict": "unknown"}
        if r.status_code == 429:
            return {"available": False, "status": 429, "reason": "rate_limited"}
        if r.status_code != 200:
            return {"available": False, "status": r.status_code}
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal, susp = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        verdict = "malicious" if mal > 0 else "suspicious" if susp > 0 else "clean"
        rep = attrs.get("reputation", None)
        asn = attrs.get("asn", "")
        as_owner = attrs.get("as_owner", "")
        return {"available": True, "malicious": mal, "suspicious": susp,
                "verdict": verdict, "reputation_raw": rep, "asn": asn,
                "as_owner": as_owner,
                "last_analysis_date": attrs.get("last_analysis_date")}
    except Exception as exc:
        log.warning("virustotal ip lookup failed: %s", type(exc).__name__)
        return {"available": False}


async def virustotal_domain(domain: str, api_key: str, timeout: float) -> dict:
    """VirusTotal domain report. Never raises."""
    if not api_key or not domain:
        return {"available": False}
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(f"https://www.virustotal.com/api/v3/domains/{domain.strip().lower()}",
                            headers={"x-apikey": api_key})
        if r.status_code == 404:
            return {"available": True, "malicious": 0, "suspicious": 0, "verdict": "unknown"}
        if r.status_code == 429:
            return {"available": False, "status": 429, "reason": "rate_limited"}
        if r.status_code != 200:
            return {"available": False, "status": r.status_code}
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal, susp = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        verdict = "malicious" if mal > 0 else "suspicious" if susp > 0 else "clean"
        return {"available": True, "malicious": mal, "suspicious": susp,
                "verdict": verdict, "registrar": attrs.get("registrar", ""),
                "creation_date": attrs.get("creation_date"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "reputation_raw": attrs.get("reputation", None)}
    except Exception as exc:
        log.warning("virustotal domain lookup failed: %s", type(exc).__name__)
        return {"available": False}


async def virustotal_url(url: str, api_key: str, timeout: float) -> dict:
    if not api_key:
        return {"available": False}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                            headers={"x-apikey": api_key})
        if r.status_code == 404:
            return {"available": True, "malicious": 0, "suspicious": 0, "verdict": "unknown"}
        if r.status_code != 200:
            return {"available": False, "status": r.status_code}
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal, susp = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        verdict = "malicious" if mal > 0 else "suspicious" if susp > 0 else "clean"
        return {"available": True, "malicious": mal, "suspicious": susp, "verdict": verdict}
    except Exception as exc:
        log.warning("virustotal url lookup failed: %s", type(exc).__name__)
        return {"available": False}


async def virustotal_hash(sha256: str, api_key: str, timeout: float) -> dict:
    if not api_key or not sha256:
        return {"available": False}
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                            headers={"x-apikey": api_key})
        if r.status_code == 404:
            return {"available": True, "malicious": 0, "suspicious": 0, "verdict": "unknown"}
        if r.status_code != 200:
            return {"available": False, "status": r.status_code}
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal, susp = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        verdict = "malicious" if mal > 0 else "suspicious" if susp > 0 else "clean"
        return {"available": True, "malicious": mal, "suspicious": susp, "verdict": verdict}
    except Exception as exc:
        log.warning("virustotal hash lookup failed: %s", type(exc).__name__)
        return {"available": False}


async def abuseipdb_check(ip: str, api_key: str, timeout: float) -> dict:
    if not api_key:
        return {"available": False}
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"available": False}
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get("https://api.abuseipdb.com/api/v2/check",
                            params={"ipAddress": ip, "maxAgeInDays": 90},
                            headers={"Key": api_key, "Accept": "application/json"})
        if r.status_code != 200:
            return {"available": False, "status": r.status_code}
        data = r.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        return {"available": True, "abuse_score": score,
                "country": data.get("countryCode", "UNKNOWN"),
                "isp": data.get("isp", "UNKNOWN"),
                "usage": data.get("usageType", "UNKNOWN"),
                "verdict": "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"}
    except Exception as exc:
        log.warning("abuseipdb lookup failed: %s", type(exc).__name__)
        return {"available": False}


async def safe_browsing_check(urls: list[str], api_key: str, timeout: float) -> dict:
    if not api_key or not urls:
        return {"available": False}
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json={"client": {"clientId": "mailsentinel-ai", "clientVersion": "1.0"},
                      "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                                     "platformTypes": ["ANY_PLATFORM"],
                                     "threatEntryTypes": ["URL"],
                                     "threatEntries": [{"url": u} for u in urls[:10]]}},
            )
        # NOTE: key is in server-side request only, never exposed to browser.
        if r.status_code != 200:
            return {"available": False, "status": r.status_code}
        matches = r.json().get("matches", [])
        flagged = {m.get("threat", {}).get("url", "") for m in matches}
        return {"available": True, "flagged": sorted(flagged), "match_count": len(matches)}
    except Exception as exc:
        log.warning("safe browsing lookup failed: %s", type(exc).__name__)
        return {"available": False}
