"""Assemble normalized AnalysisResult from pipeline outputs (SOC-grade)."""
from __future__ import annotations

from datetime import datetime, timezone

from ..models.analysis import AiVerdict
from .build_parts import auth_checks
from .confidence import confidence_dimensions
from .evidence import make_evidence, unavailable_evidence
from .forensics import build_forensic_timeline
from .graph_parts import attachment_intel, build_graph
from .provider_health import provider_health_snapshot
from .scoring import fuse_score, severity_for


def build_result(parsed, sha, signals, url_intel, ip_intel, dom_intel,
                 geo, iocs, ai: AiVerdict, ai_used: bool,
                 score: int, indicators: list[dict], threat: str,
                 auth_fx=None, attach_fore=None,
                 vt_hashes=None, settings=None) -> dict:
    now = datetime.now(timezone.utc)
    severity = ai.severity if ai_used else severity_for(score)
    if ai_used:
        threat = ai.threat_type or threat
    breakdown = list(getattr(fuse_score, "last_breakdown", []) or [])
    sender_domain = signals["sender_domain"]
    dom_hit = next((d for d in dom_intel if d["domain"] == sender_domain), None)
    auth_fx = auth_fx or {}
    analyzed_iso = now.isoformat()
    tl = build_forensic_timeline(parsed, analyzed_iso)
    bad_url = next((u for u in url_intel if u["reputation"] in ("MALICIOUS", "SUSPICIOUS")), None)
    bad_ip = next((p for p in ip_intel if p["reputation"] in ("MALICIOUS", "SUSPICIOUS")), None)
    vt_hashes = vt_hashes or {}
    bad_att = any(h.get("available") and h.get("verdict") == "malicious" for h in vt_hashes.values())
    cs = severity if severity != "SAFE" else "LOW"
    look_hit, look_brand = signals["lookalike"]
    chain: list[dict] = []
    chain.append({"label": "INITIAL DELIVERY", "stage": "Initial Delivery",
                  "detail": f"Subject: {(parsed.get('subject') or '')[:60]}",
                  "severity": "LOW", "evidence": "From/Message-ID headers",
                  "iocs": [parsed.get("from", "")], "confidence": 80, "source": "headers"})
    if signals["reply_mismatch"] or look_hit or auth_fx.get("reply_suspicious"):
        chain.append({"label": "SENDER ANOMALY", "stage": "Sender / Identity Anomaly",
                      "detail": f"Reply-To {parsed.get('replyTo') or 'not set'}",
                      "severity": cs, "evidence": "From/Reply-To/Return-Path comparison",
                      "iocs": [parsed.get("from", "")], "confidence": 80, "source": "headers"})
    spf, dkim, dmarc = parsed.get("spfHeader"), parsed.get("dkimHeader"), parsed.get("dmarcHeader")
    if spf == "FAIL" or dkim == "FAIL" or dmarc == "FAIL":
        chain.append({"label": "AUTH FAILURE", "stage": "Authentication Failure",
                      "detail": f"SPF {spf} DKIM {dkim} DMARC {dmarc}",
                      "severity": cs, "evidence": "Authentication-Results",
                      "iocs": [], "confidence": 90, "source": "Authentication-Results"})
    if signals.get("has_cred") or signals.get("has_urgency"):
        chain.append({"label": "SOCIAL ENGINEERING", "stage": "Social Engineering",
                      "detail": "Credential/urgency language in body",
                      "severity": cs, "evidence": "Body keyword heuristic",
                      "iocs": [], "confidence": 60, "source": "local-heuristics"})
    if bad_url:
        chain.append({"label": "MALICIOUS LINK", "stage": "Malicious Link",
                      "detail": bad_url["url"][:80], "severity": cs,
                      "evidence": f"Provider verdict {bad_url.get('reputation')}",
                      "iocs": [bad_url["url"]], "confidence": 85,
                      "source": "VirusTotal/SafeBrowsing"})
    if bad_att or signals.get("risky_attachments"):
        names = [a.get("filename", "") for a in (parsed.get("attachments", []) or [])][:3]
        chain.append({"label": "MALWARE ATTACHMENT", "stage": "Malware Attachment",
                      "detail": ", ".join(names) or "risky attachment",
                      "severity": cs, "evidence": "VT-by-hash + extension forensics",
                      "iocs": names, "confidence": 85 if bad_att else 60,
                      "source": "VirusTotal/file-forensics"})
    if bad_ip:
        chain.append({"label": "C2 INDICATOR", "stage": "Command-and-Control Indicator",
                      "detail": f"{bad_ip['ip']} abuse={bad_ip.get('abuseScore')}",
                      "severity": cs, "evidence": "AbuseIPDB/VT IP reputation",
                      "iocs": [bad_ip["ip"]], "confidence": 75,
                      "source": "AbuseIPDB/VirusTotal"})
    chain.append({"label": "VERDICT", "stage": "Verdict",
                  "detail": f"{severity} - {threat}", "severity": cs,
                  "evidence": "Fusion score + analyst assessment",
                  "iocs": [], "confidence": 70, "source": "fusion-engine"})
    recs = list(ai.recommended_actions) if ai_used and ai.recommended_actions else []
    if not recs:
        recs = (["No action required — deliver to inbox", "Keep the message for 30 days of retention",
                 "Add sender domain to the trusted-sender baseline"]
                if severity in ("SAFE", "LOW") else
                ["Quarantine Email", "Block Malicious Domain", "Block Suspicious IP",
                 "Search for Similar Emails", "Reset Potentially Exposed Credentials",
                 "Notify Security Administrator", "Add IOC to Blocklist"])
    hrisk = severity if severity != "SAFE" else "LOW"
    hrep = "CLEAN" if severity in ("SAFE", "LOW") else "SUSPICIOUS"
    iocs = [*iocs, {"type": "Hash", "value": sha, "reputation": hrep,
                    "risk": hrisk, "source": "Message SHA-256 (server)"}]

    def rep(r: str) -> str:
        return r if r in ("CLEAN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN") else "UNKNOWN"

    g = dict(geo) if geo else {}
    geo_out = None
    if geo:
        geo_out = {"ip": g.get("ip", ""), "reputation": "UNKNOWN",
                   "country": g.get("country", "UNKNOWN"),
                   "countryCode": g.get("countryCode", "--"),
                   "city": g.get("city", "UNKNOWN"),
                   "region": g.get("region", "UNKNOWN"),
                   "isp": g.get("isp", "UNKNOWN"), "asn": g.get("asn", "UNKNOWN"),
                   "abuseScore": 0, "risk": "LOW",
                   "lat": g.get("lat", 0.0), "lon": g.get("lon", 0.0),
                   "continent": g.get("continent", "UNKNOWN"),
                   "postal_code": g.get("postal_code", ""),
                   "accuracy_radius_km": g.get("accuracy_radius_km"),
                   "timezone": g.get("timezone", "UNKNOWN"),
                   "organization": g.get("organization", "UNKNOWN"),
                   "connection_type": g.get("connection_type", "UNKNOWN"),
                   "hosting": bool(g.get("hosting", False)),
                   "proxy": bool(g.get("proxy", False)),
                   "vpn": bool(g.get("vpn", False)),
                   "tor": bool(g.get("tor", False)),
                   "anonymizer_type": g.get("anonymizer_type", ""),
                   "geo_provider": g.get("provider", ""),
                   "providers": {}, "geo": g}
    attachments = attachment_intel(parsed.get("attachments", []), severity,
                                   vt_results=vt_hashes, forensics=attach_fore)

    url_out = []
    for u in url_intel:
        uu = dict(u)
        notes = u.get("notes", []) if isinstance(u.get("notes"), list) else []
        uu["indicators"] = list(notes)[:4]
        uu["confidence"] = 85 if u.get("reputation") in ("MALICIOUS", "CLEAN") else 50
        url_out.append(uu)

    ev: list[dict] = []
    spf = parsed.get("spfHeader")
    if spf in ("PASS", "FAIL"):
        ev.append(make_evidence(category="authentication", title=f"SPF {spf}",
                                severity="HIGH" if spf == "FAIL" else "LOW", confidence=90,
                                observed_value=str(spf), source="Authentication-Results",
                                provider="header", evidence="SPF result observed in headers.",
                                status="confirmed", observed_vs_inferred="observed"))
    else:
        ev.append(make_evidence(category="authentication", title="SPF result unavailable",
                                severity="LOW", confidence=40, source="headers", provider="header",
                                evidence="No SPF result in headers.", status="unknown"))
    for u in url_intel[:10]:
        if u.get("reputation") in ("MALICIOUS", "SUSPICIOUS"):
            ev.append(make_evidence(category="url", title=f"URL flagged {u['reputation']}",
                                    severity="CRITICAL" if u["reputation"] == "MALICIOUS" else "HIGH",
                                    confidence=85, observed_value=u["url"][:300],
                                    source="VirusTotal/SafeBrowsing", provider="virustotal+google",
                                    evidence="; ".join(u.get("notes", [])[:3]),
                                    status="confirmed", observed_vs_inferred="observed",
                                    related_ioc=u["url"][:200]))
    if ai_used:
        for r in (ai.suspected_findings or ai.reasons or [])[:5]:
            ev.append(make_evidence(category="ai", title="AI suspected finding", severity="MEDIUM",
                                    confidence=ai.confidence, observed_value=str(r)[:300],
                                    source="AI", provider="openai", evidence=str(r)[:500],
                                    status="suspicious", observed_vs_inferred="inferred"))
    else:
        ev.append(unavailable_evidence("ai", "AI assessment unavailable", "openai",
                                       "No key or unreachable."))
    hits = sum(u.get("reputation") in ("MALICIOUS", "SUSPICIOUS", "CLEAN") for u in url_intel)
    hits += sum(p.get("reputation") in ("MALICIOUS", "SUSPICIOUS", "CLEAN") for p in ip_intel)
    total = max(1, len(url_intel) + len(ip_intel))
    conf = confidence_dimensions(
        parsed=parsed, signals=signals,
        intel={"virustotal_malicious": sum(1 for u in url_intel if u.get("reputation") == "MALICIOUS"),
               "max_abuse_score": max([p.get("abuseScore", 0) for p in ip_intel] + [0])},
        ai_used=ai_used, ai_conf=ai.confidence if ai_used else 0,
        geo=geo, provider_hits=hits, provider_total=total)
    health = provider_health_snapshot(settings, {}) if settings is not None else {}
    graph = build_graph(parsed, ip_intel, url_intel, dom_intel, parsed.get("attachments", []))

    return {
        "investigationId": f"INV-{now.year}-{sha[:6].upper()}",
        "messageSha256": sha, "analyzedAt": analyzed_iso, "mode": "LIVE",
        "email": {**parsed, "htmlBody": ""}, "riskScore": score, "threatType": threat,
        "severity": severity, "confidence": conf["final_verdict_confidence"], "indicators": indicators,
        "senderAnalysis": {"email": parsed.get("from") or "UNKNOWN",
                           "displayName": parsed.get("displayName") or "UNKNOWN",
                           "domain": sender_domain or "UNKNOWN",
                           "replyTo": parsed.get("replyTo") or "Not set",
                           "replyToMismatch": signals["reply_mismatch"],
                           "domainAge": f"{dom_hit['ageDays']} days" if dom_hit and dom_hit.get("ageDays") is not None else "UNKNOWN",
                           "domainReputation": rep(dom_hit["reputation"]) if dom_hit else "UNKNOWN",
                           "authStatus": f"SPF {parsed.get('spfHeader')} · DKIM {parsed.get('dkimHeader')} · DMARC {parsed.get('dmarcHeader')}",
                           "risk": severity if (signals["reply_mismatch"] or look_hit) else "LOW",
                           "lookalike": look_hit, **({"lookalikeOf": look_brand} if look_brand else {})},
        "authenticationAnalysis": auth_checks(parsed),
        "urlAnalysis": url_out, "ipAnalysis": ip_intel, "domainAnalysis": dom_intel,
        "geolocation": geo_out, "iocs": iocs,
        "attachments": attachments,
        "recommendations": recs, "timeline": tl, "attackChain": chain,
        "evidence": ev, "scoreBreakdown": breakdown,
        "confidenceBreakdown": conf, "authForensics": auth_fx,
        "investigationGraph": graph,
        "aiAssessment": {"used": ai_used,
                         "classification": ai.classification or ai.threat_type,
                         "executive_summary": ai.executive_summary or ai.summary,
                         "confirmed_findings": ai.confirmed_findings,
                         "suspected_findings": ai.suspected_findings or ai.reasons,
                         "unknowns": ai.unknowns, "attack_techniques": ai.attack_techniques,
                         "reasoning_summary": ai.reasoning_summary,
                         "confidence": ai.confidence, "severity": ai.severity,
                         "recommended_actions": ai.recommended_actions},
        "providerHealth": health,
    }
