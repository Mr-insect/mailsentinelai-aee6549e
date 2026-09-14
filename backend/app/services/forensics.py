"""Forensic auth + timeline + attachment + chain builders from real headers."""
from __future__ import annotations

import email.utils
import hashlib
import re
from datetime import datetime, timezone

RISKY_EXT = (".exe", ".js", ".vbs", ".scr", ".jar", ".iso", ".bat", ".cmd",
             ".ps1", ".lnk", ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z")
EXEC_EXT = (".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
            ".lnk", ".msi", ".com", ".pif")


def _domain_of_addr(v: str) -> str:
    _, addr = email.utils.parseaddr(v or "")
    return (addr.split("@")[-1].lower() if "@" in addr else "")


def auth_forensics(parsed: dict) -> dict:
    """SPF/DKIM/DMARC/alignment with explicit NONE vs UNKNOWN."""
    spf = parsed.get("spfHeader", "UNKNOWN")
    dkim = parsed.get("dkimHeader", "UNKNOWN")
    dmarc = parsed.get("dmarcHeader", "UNKNOWN")
    from_dom = _domain_of_addr(parsed.get("from", ""))
    ret_dom = _domain_of_addr(parsed.get("returnPath", ""))
    reply_dom = _domain_of_addr(parsed.get("replyTo", ""))
    aligned = "UNKNOWN"
    if from_dom and ret_dom:
        aligned = "PASS" if from_dom == ret_dom else "FAIL"
    reply_susp = bool(reply_dom) and bool(from_dom) and reply_dom != from_dom
    ret_differs = bool(ret_dom) and bool(from_dom) and ret_dom != from_dom
    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "alignment": aligned,
            "from_domain": from_dom, "return_domain": ret_dom,
            "reply_domain": reply_dom, "reply_suspicious": reply_susp,
            "return_differs": ret_differs}


def parse_received_hops(received: list[str]) -> list[dict]:
    hops: list[dict] = []
    # Received headers are newest-first; reverse for chronological timeline.
    for raw in list(received or [])[::-1][:12]:
        ips = re.findall(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", raw)
        hosts = re.findall(r"(?:from|by)\s+([A-Za-z0-9.\-]+)", raw,
                           re.IGNORECASE)
        try:
            dt = email.utils.parsedate_to_datetime(raw.rsplit(";", 1)[-1].strip())
            ts = dt.astimezone(timezone.utc).isoformat() if dt else None
        except Exception:
            ts = None
        hops.append({"timestamp": ts, "from_host": hosts[0] if hosts else "",
                     "by_host": hosts[1] if len(hosts) > 1 else "",
                     "ip": ips[0] if ips else "",
                     "evidence": raw[:400]})
    return hops


def build_forensic_timeline(parsed: dict, analyzed_at: str) -> list[dict]:
    tl: list[dict] = []
    hops = parse_received_hops(parsed.get("received", []))
    if parsed.get("date") and parsed.get("date") != "UNKNOWN":
        tl.append({"time": parsed["date"], "label": "Message Date header",
                   "detail": f"Date: {parsed['date'][:120]}",
                   "evidence_source": "Date header"})
    for i, h in enumerate(hops):
        tl.append({
            "time": h["timestamp"] or "UNKNOWN",
            "label": f"Mail hop {i + 1}",
            "detail": f"{h['from_host'] or '?'} -> {h['by_host'] or '?'}"
                      + (f" [{h['ip']}]" if h["ip"] else ""),
            "evidence_source": f"Received header {i + 1}"})
    if not tl:
        tl.append({"time": "UNKNOWN", "label": "No transport evidence",
                   "detail": "No Date or Received headers present.",
                   "evidence_source": "parser"})
    tl.append({"time": analyzed_at, "label": "Investigation completed",
               "detail": "Evidence compiled into AnalysisResult.",
               "evidence_source": "analyzer"})
    return tl


def attachment_forensics(attachments: list[dict]) -> list[dict]:
    out = []
    for a in attachments or []:
        name = str(a.get("filename", "") or "")
        low = name.lower()
        ext = ("." + low.rsplit(".", 1)[-1]) if "." in low else ""
        double_ext = low.count(".") >= 2 and any(
            low.endswith(e) for e in EXEC_EXT + (".pdf", ".docx", ".xlsx"))
        ctype = str(a.get("contentType", "") or "")
        mismatch = ((ext in EXEC_EXT and "executable" not in ctype
                     and "octet" not in ctype and "zip" not in ctype)
                    or (low.endswith((".docm", ".xlsm", ".pptm"))
                        and "macro" not in ctype and "zip" not in ctype
                        and "office" not in ctype and "octet" not in ctype))
        risky = low.endswith(RISKY_EXT) or mismatch or double_ext
        macro = low.endswith((".docm", ".xlsm", ".pptm"))
        archive = low.endswith((".zip", ".rar", ".7z", ".iso"))
        notes = []
        if mismatch:
            notes.append("Extension/MIME mismatch.")
        if double_ext:
            notes.append("Double extension (masquerade risk).")
        if macro:
            notes.append("Macro-enabled Office file.")
        if archive:
            notes.append("Archive — may hide nested payloads.")
        if low.endswith(EXEC_EXT):
            notes.append("Executable/script type.")
        out.append({"filename": name, "extension": ext,
                    "double_extension": double_ext,
                    "extension_mismatch": mismatch, "macro_enabled": macro,
                    "archive": archive, "risky": risky, "notes": notes,
                    "sha256": a.get("sha256", ""),
                    "sizeBytes": a.get("sizeBytes", 0)})
    return out
