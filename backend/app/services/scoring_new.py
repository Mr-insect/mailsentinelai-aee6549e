"""Evidence-weighted fusion scoring with explainable breakdown (bounded 0-100)."""
from __future__ import annotations


def severity_for(score: int) -> str:
    if score >= 81:
        return "CRITICAL"
    if score >= 61:
        return "HIGH"
    if score >= 31:
        return "MEDIUM"
    if score >= 5:
        return "LOW"
    return "SAFE"


def fuse_score(signals: dict, intel: dict, ai_score: int | None,
               ai_used: bool) -> tuple[int, list[dict], str]:
    score = 0
    breakdown: list[dict] = []
    indicators: list[dict] = []

    def add(id_, name, hit, weight, explain, icon="shield"):
        nonlocal score
        indicators.append({"id": id_, "name": name,
                           "status": "DETECTED" if hit else "CLEAR",
                           "explanation": explain, "weight": weight,
                           "icon": icon})
        if hit:
            score += weight
            breakdown.append({"category": name, "points": weight,
                              "reason": explain})

    add("auth", "Authentication failure",
        signals["spf_fail"] or signals["dkim_fail"] or signals["dmarc_fail"],
        15, f"SPF fail={signals['spf_fail']} DKIM fail={signals['dkim_fail']} "
            f"DMARC fail={signals['dmarc_fail']}", "key")
    vt_bad = (intel.get("virustotal_malicious", 0) > 0
              or intel.get("safebrowsing_flagged", 0) > 0)
    add("url", "Malicious URL infrastructure",
        vt_bad or bool(signals["suspicious_tld_urls"]), 35,
        f"VT malicious={intel.get('virustotal_malicious', 0)} SB flagged="
        f"{intel.get('safebrowsing_flagged', 0)}", "link")
    add("ip", "Malicious sender IP",
        (intel.get("max_abuse_score", 0) or 0) >= 50, 20,
        f"max AbuseIPDB={intel.get('max_abuse_score', 0)}", "server")
    add("attach", "Attachment reputation",
        bool(intel.get("attachment_malicious", 0)), 30,
        f"VT-known malicious attachments="
        f"{intel.get('attachment_malicious', 0)}", "paperclip")
    add("sender", "Suspicious sender",
        signals["reply_mismatch"] or signals["lookalike"][0], 12,
        f"reply_mismatch={signals['reply_mismatch']} lookalike="
        f"{signals['lookalike']}", "user")
    add("domain", "Domain anomaly",
        bool(signals.get("domain_anomaly")), 10, "Lookalike/TLD/shortener "
        "signals on sender or link domains.", "globe")
    add("cred", "Credential-harvesting language", signals["has_cred"], 10,
        "Credential keywords present.", "key-round")
    add("urg", "Urgency / pressure language", signals["has_urgency"], 5,
        "Urgency keywords present.", "alarm-clock")
    add("short", "Link shortener / redirect",
        bool(signals["shortener_urls"]) or bool(signals["http_urls"]), 5,
        "Shortened or plain-http links.", "globe")
    add("risky-att", "Risky attachment shape",
        bool(signals["risky_attachments"]), 15,
        f"{len(signals['risky_attachments'])} risky attachments.", "paperclip")

    if ai_used and ai_score is not None:
        before = score
        score = round(0.75 * score + 0.25 * max(0, min(100, ai_score)))
        breakdown.append({"category": "AI analyst assessment",
                          "points": score - before,
                          "reason": f"AI risk {ai_score} blended at 25% "
                          "weight (assistant, not source of truth)."})

    # Benign evidence: strong auth passes slightly reduce score.
    if (not signals["spf_fail"] and not signals["dkim_fail"]
            and not signals["dmarc_fail"] and not vt_bad
            and (intel.get("max_abuse_score", 0) or 0) < 10 and score > 0):
        score = max(0, score - 5)
        breakdown.append({"category": "Benign evidence", "points": -5,
                          "reason": "Authentication passed, no live intel "
                          "hits; small negative adjustment."})

    score = max(0, min(100, score))

    if score <= 4 and not vt_bad and (intel.get("max_abuse_score", 0) or 0) < 10:
        threat = "Legitimate Email"
    elif signals["risky_attachments"] or intel.get("attachment_malicious"):
        threat = "Malware Delivery"
    elif signals["has_cred"] or vt_bad:
        threat = "Credential Phishing"
    elif score >= 31:
        threat = "Suspicious Email"
    else:
        threat = "Likely Safe"
    return score, indicators, threat


def score_breakdown_text(breakdown: list[dict]) -> list[str]:
    return [f"{b['category']}: {'+' if b['points'] >= 0 else ''}"
            f"{b['points']} ({b['reason']})" for b in breakdown]
