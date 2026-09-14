"""Deterministic heuristic checks + sanitization for AI input."""
from __future__ import annotations

import re

CREDENTIAL = ["verify your account", "confirm your password", "login to continue",
              "sign in to verify", "update your credentials", "account will be suspended",
              "reset your password", "validate your account", "confirm your identity"]
URGENCY = ["urgent", "immediately", "within 24 hours", "final notice", "action required",
           "failure to comply", "suspended", "last warning", "act now"]
RISKY_EXT = (".exe", ".js", ".vbs", ".scr", ".jar", ".iso", ".bat", ".cmd",
             ".docm", ".xlsm", ".htm", ".html", ".zip", ".rar", ".7z")
SUSP_TLD = (".zip", ".top", ".xyz", ".click", ".link", ".tk", ".ru", ".cn", ".gq", ".rest")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly")
BRANDS = ("university", "microsoft", "office365", "paypal", "google",
          "apple", "amazon", "netflix", "dhl", "bank")


def lookalike(domain: str):
    bare = domain.replace("www.", "")
    label = bare.split(".")[0] if bare else ""
    for brand in BRANDS:
        if brand in bare and not bare.endswith(f"{brand}.com") and not bare.endswith(".edu"):
            return True, brand
    if re.search(r"-(secure|login|verify|account|support|update)\b", bare):
        return True, bare.split("-")[0]
    return False, None


def domain_of(value: str) -> str:
    if "@" in value:
        return value.split("@")[-1].lower()
    m = re.match(r"https?://([^/?#:]+)", value, re.IGNORECASE)
    return m.group(1).lower() if m else value.lower()


def heuristic_signals(parsed: dict) -> dict:
    body = (parsed.get("body") or "").lower()
    urls = parsed.get("urls") or []
    sender_domain = domain_of(parsed.get("from") or "")
    dom_anomaly = any(domain_of(u).endswith(t) for u in urls for t in SUSP_TLD)
    dom_anomaly = dom_anomaly or any(domain_of(u) in SHORTENERS for u in urls)
    lk, _ = lookalike(sender_domain)
    dom_anomaly = dom_anomaly or lk
    return {
        "sender_domain": sender_domain,
        "reply_mismatch": bool(parsed.get("replyTo")) and parsed.get("replyTo", "").lower() not in (parsed.get("from") or "").lower(),
        "has_cred": any(k in body for k in CREDENTIAL),
        "has_urgency": any(k in body for k in URGENCY),
        "risky_attachments": [a for a in parsed.get("attachments", []) if any(str(a.get("filename", "")).lower().endswith(e) for e in RISKY_EXT)],
        "suspicious_tld_urls": [u for u in urls if any(domain_of(u).endswith(t) for t in SUSP_TLD)],
        "shortener_urls": [u for u in urls if any(domain_of(u) == s for s in SHORTENERS)],
        "http_urls": [u for u in urls if u.lower().startswith("http://")],
        "spf_fail": parsed.get("spfHeader") == "FAIL",
        "dkim_fail": parsed.get("dkimHeader") == "FAIL",
        "dmarc_fail": parsed.get("dmarcHeader") == "FAIL",
        "lookalike": lookalike(sender_domain),
        "domain_anomaly": dom_anomaly,
    }


def sanitize_for_ai(parsed: dict, intel: dict, max_body: int, max_urls: int, extra: dict | None = None) -> dict:
    """Strip PII-heavy content: truncate body, drop raw headers/html/payloads.

    Sends a structured evidence package (not the full raw email).
    """
    base = {
        "subject": (parsed.get("subject") or "")[:300],
        "from_domain": domain_of(parsed.get("from") or ""),
        "auth": {"spf": parsed.get("spfHeader"), "dkim": parsed.get("dkimHeader"), "dmarc": parsed.get("dmarcHeader")},
        "reply_mismatch": bool(parsed.get("replyTo")),
        "body_excerpt": (parsed.get("body") or "")[:max_body],
        "urls": (parsed.get("urls") or [])[:max_urls],
        "domains": (parsed.get("domains") or [])[:max_urls],
        "ip_count": len(parsed.get("ips") or []),
        "attachment_names": [str(a.get("filename", ""))[:120] for a in parsed.get("attachments", [])][:10],
        "intel_summary": intel,
    }
    if extra:
        base["structured_evidence"] = extra
    return base
