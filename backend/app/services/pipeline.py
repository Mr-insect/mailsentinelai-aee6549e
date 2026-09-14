"""Pipeline part 2: orchestrate parse -> enrich -> AI -> result."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..models.analysis import AnalysisResult
from .ai_analyzer import ai_verdict
from .auth_verify import verify_authentication
from .cache import DOMAIN_CACHE, HASH_CACHE, norm_domain
from .dns_intel import analyze_domain_dns
from .domain_intel import analyze_domain_local
from .enrich import MAX_DOMAINS, enrich_ips, enrich_urls, rep_live, risk_of
from .forensics import attachment_forensics, auth_forensics
from .heuristics import heuristic_signals, sanitize_for_ai
from .parse_core import parse_eml
from .result_builder import build_result
from .scoring import fuse_score
from .threat_intel import virustotal_domain, virustotal_hash

log = logging.getLogger("mailsentinel.pipeline")


async def enrich_domains(parsed: dict, url_intel: list[dict],
                         signals: dict, settings) -> list[dict]:
    sender_dom = signals.get("sender_domain", "")
    reply_raw = parsed.get("replyTo") or ""
    reply_dom = reply_raw.split("@")[-1].lower() if "@" in reply_raw else ""
    out = []
    for d in list(dict.fromkeys(parsed.get("domains", [])))[:MAX_DOMAINS]:
        key = "domain:" + norm_domain(d)
        cached = DOMAIN_CACHE.get(key)
        if cached is not None:
            out.append(dict(cached))
            continue
        local = analyze_domain_local(d, sender_dom, reply_dom)
        vt = await virustotal_domain(d, settings.VIRUSTOTAL_API_KEY,
                                     settings.EXTERNAL_TIMEOUT_S)
        vrep = rep_live(vt.get("verdict", "unknown"), vt.get("available", False))
        url_hit = next((x for x in url_intel if x.get("domain") == d
                        and x.get("reputation") in ("MALICIOUS", "SUSPICIOUS")), None)
        rep = vrep
        if url_hit and url_hit.get("reputation") == "MALICIOUS":
            rep = "MALICIOUS"

        # Real DNS intelligence (A/AAAA/MX/NS/TXT/CNAME/PTR/DNSSEC/existence).
        # Failures degrade to UNKNOWN; they are never treated as malicious
        # and never turned into fabricated records.
        dns_detail = await analyze_domain_dns(d, settings.EXTERNAL_TIMEOUT_S)

        # Real registration age ONLY from a configured provider (VirusTotal
        # creation_date). Without a provider or data -> None (UNKNOWN),
        # never a guess.
        creation = vt.get("creation_date") if vt.get("available") else None
        age_days = None
        if isinstance(creation, (int, float)) and creation > 0:
            try:
                age_days = max(0, (datetime.now(timezone.utc) -
                                   datetime.fromtimestamp(
                                       creation, tz=timezone.utc)).days)
            except Exception:
                age_days = None

        notes = list(local.get("notes", []))
        if vt.get("available"):
            notes.append(f"VirusTotal: {vt.get('malicious', 0)} malicious")
            if vt.get("registrar"):
                notes.append(f"Registrar: {vt['registrar']}")
        elif settings.VIRUSTOTAL_API_KEY:
            notes.append("VirusTotal domain lookup unavailable.")
        else:
            notes.append("VirusTotal not configured - UNKNOWN.")
        notes.extend(dns_detail["notes"])
        notes.append("Domain age is supporting evidence only, never decisive.")
        row = {"domain": d, "ageDays": age_days,
               "registrar": vt.get("registrar", "") or "UNKNOWN",
               "dns": dns_detail["summary"],
               "dnsStatus": dns_detail["status"],
               "dnssec": dns_detail["dnssec"],
               "dnsRecords": dns_detail["records"],
               "dnsLookups": dns_detail["lookups"],
               "resolvedIps": dns_detail["resolved_ips"],
               "reputation": rep,
               "risk": risk_of(rep if rep != "UNKNOWN" else "UNKNOWN"),
               "lookalike": bool(local.get("lookalike")),
               "registrable": local.get("registrable", ""),
               "subdomain": local.get("subdomain", ""),
               "punycode": bool(local.get("punycode")),
               "shortener": bool(local.get("shortener")),
               "suspicious_tld": bool(local.get("suspicious_tld")),
               "depth": int(local.get("depth", 0)),
               "lookalike_of": local.get("lookalike_of"),
               "sender_mismatch": bool(local.get("sender_mismatch")),
               "reply_mismatch": bool(local.get("reply_mismatch")),
               "notes": notes[:8],
               "providers": {"virustotal": vt,
                             "dns": {"status": dns_detail["status"],
                                     "dnssec": dns_detail["dnssec"]}}}
        DOMAIN_CACHE.set(key, row, ttl_s=12 * 3600)
        out.append(row)
    return out



async def analyze_bytes(raw: bytes, settings) -> AnalysisResult:
    out = parse_eml(raw)
    parsed, sha = out["parsed"], out["message_sha256"]

    # Local SPF/DKIM/DMARC verification (RFC 7208/6376/7489).  Authentication-
    # Results headers are NOT trusted for scoring: their claims are captured
    # first and kept as separate observed evidence in authForensics.
    upstream_auth = {"spf": parsed.get("spfHeader"),
                     "dkim": parsed.get("dkimHeader"),
                     "dmarc": parsed.get("dmarcHeader")}
    try:
        auth_local = await verify_authentication(parsed, raw,
                                                 settings.EXTERNAL_TIMEOUT_S)
        parsed["spfHeader"] = auth_local["spfHeader"]
        parsed["dkimHeader"] = auth_local["dkimHeader"]
        parsed["dmarcHeader"] = auth_local["dmarcHeader"]
    except Exception as exc:  # verification must never break the pipeline
        log.warning("local authentication verification unavailable: %s",
                    type(exc).__name__)
        auth_local = None

    signals = heuristic_signals(parsed)

    url_intel, vt_mal, sb_n = await enrich_urls(parsed, settings)
    ip_intel, geos, max_abuse = await enrich_ips(parsed, settings)
    dom_intel = await enrich_domains(parsed, url_intel, signals, settings)
    if any(d.get("lookalike") or d.get("suspicious_tld") or d.get("shortener")
           for d in dom_intel):
        signals["domain_anomaly"] = True

    fore = attachment_forensics(parsed.get("attachments", []))
    vt_hashes: dict = {}
    attach_mal = 0
    for a in parsed.get("attachments", [])[:5]:
        sh = a.get("sha256", "") or ""
        if not sh:
            continue
        key = "hash:" + sh
        h = HASH_CACHE.get(key)
        if h is None:
            h = await virustotal_hash(sh, settings.VIRUSTOTAL_API_KEY,
                                      settings.EXTERNAL_TIMEOUT_S)
            HASH_CACHE.set(key, h, ttl_s=24 * 3600)
        vt_hashes[sh] = h
        if h.get("available") and h.get("verdict") == "malicious":
            vt_mal += 1
            attach_mal += 1

    intel = {"virustotal_malicious": vt_mal, "safebrowsing_flagged": sb_n,
             "max_abuse_score": max_abuse, "attachment_malicious": attach_mal,
             "vt_hash_verdict": "checked"}
    score, indicators, threat = fuse_score(signals, intel, None, False)
    auth_fx = auth_forensics(parsed)
    # Keep upstream Authentication-Results claims separate from local
    # verification: observed header claims vs locally verified facts.
    auth_fx["upstream_authentication_results"] = upstream_auth
    auth_fx["local_verification"] = (auth_local or {}).get("local") or {
        "available": False}
    evidence = sanitize_for_ai(parsed, intel, settings.AI_MAX_BODY_CHARS,
                               settings.AI_MAX_URLS,
                               extra={"auth_forensics": auth_fx,
                                      "hop_count": len(parsed.get("received", []))})
    ai, ai_used = await ai_verdict(evidence, settings.OPENAI_API_KEY,
                                   settings.OPENAI_MODEL, settings.AI_TIMEOUT_S)
    if ai_used:
        score, indicators, threat = fuse_score(signals, intel, ai.risk_score, True)

    iocs: list[dict] = []
    for u in parsed.get("urls", []):
        m = next((x for x in url_intel if x["url"] == u), None)
        iocs.append({"type": "URL", "value": u, "reputation": m["reputation"] if m else "UNKNOWN",
                     "risk": m["risk"] if m else "LOW", "source": "Body link (live verdict)"})
    for d in parsed.get("domains", []):
        m = next((x for x in dom_intel if x["domain"] == d), None)
        iocs.append({"type": "Domain", "value": d, "reputation": m["reputation"] if m else "UNKNOWN",
                     "risk": m["risk"] if m else "LOW", "source": "Sender/link domain"})
    for p in ip_intel:
        iocs.append({"type": "IP", "value": p["ip"], "reputation": p["reputation"],
                     "risk": p["risk"], "source": "Received chain (AbuseIPDB+VT)"})
    for e in parsed.get("emails", [])[:10]:
        iocs.append({"type": "Email", "value": e, "reputation": "UNKNOWN",
                     "risk": "LOW", "source": "Header/body address"})
    for a in parsed.get("attachments", []):
        if a.get("sha256"):
            h = vt_hashes.get(a["sha256"], {})
            rep = "MALICIOUS" if h.get("verdict") == "malicious" else \
                  "CLEAN" if h.get("verdict") == "clean" else "UNKNOWN"
            iocs.append({"type": "Hash", "value": a["sha256"], "reputation": rep,
                         "risk": "CRITICAL" if rep == "MALICIOUS" else "MEDIUM",
                         "source": f"Attachment {str(a.get('filename', ''))[:60]} (VT by hash)"})
            iocs.append({"type": "File", "value": a.get("filename", ""), "reputation": rep,
                         "risk": "MEDIUM", "source": "Attachment name"})

    geo = geos[0] if geos else None
    data = build_result(parsed, sha, signals, url_intel, ip_intel, dom_intel,
                        geo, iocs, ai, ai_used, score, indicators, threat,
                        auth_fx=auth_fx, attach_fore=fore,
                        vt_hashes=vt_hashes, settings=settings)
    return AnalysisResult(**data)
