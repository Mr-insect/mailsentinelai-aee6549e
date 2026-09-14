"""Shared builders for auth checks, timeline, attack chain, attachments."""
from __future__ import annotations

EXPLAIN = {
    "SPF": {"PASS": "Sending IP is authorized by the domain's SPF record.",
            "FAIL": "Sender IP is not authorized by the domain's SPF policy.",
            "SUSPICIOUS": "SPF record is missing or returned a neutral result.",
            "NONE": "No SPF record / result published for this path.",
            "UNKNOWN": "No SPF result was present in the message headers."},
    "DKIM": {"PASS": "Cryptographic signature verified.",
             "FAIL": "Signature verification failed.",
             "SUSPICIOUS": "A DKIM signature exists but no verification result was recorded.",
             "NONE": "No DKIM signature present on the message.",
             "UNKNOWN": "No DKIM signature or result was present."},
    "DMARC": {"PASS": "Domain alignment satisfied the published DMARC policy.",
              "FAIL": "Domain alignment/authentication policy failed.",
              "SUSPICIOUS": "No DMARC policy published for the sending domain.",
              "NONE": "No DMARC record / result available.",
              "UNKNOWN": "No DMARC result was present in the message headers."},
}

RISKY_EXT = (".exe", ".js", ".vbs", ".scr", ".jar", ".iso", ".bat",
             ".cmd", ".docm", ".xlsm", ".zip", ".rar", ".7z")


def auth_checks(parsed: dict) -> list[dict]:
    out = []
    for name in ("SPF", "DKIM", "DMARC"):
        st = parsed.get(f"{name.lower()}Header", "UNKNOWN")
        if st not in EXPLAIN[name]:
            st = "UNKNOWN"
        out.append({"name": name, "status": st, "explanation": EXPLAIN[name][st]})
    return out
