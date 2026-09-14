"""VT-aware attachment verdicts + investigation graph builder."""
from __future__ import annotations


def attachment_intel(attachments: list[dict], severity: str,
                     vt_results: dict | None = None,
                     forensics: list[dict] | None = None) -> list[dict]:
    out = []
    vt_results = vt_results or {}
    fore = {f.get("sha256", ""): f for f in (forensics or [])}
    for a in attachments:
        sha = a.get("sha256", "") or ""
        vt = vt_results.get(sha, {})
        f = fore.get(sha, {})
        if vt.get("available") and vt.get("verdict") == "malicious":
            verdict, rep = "KNOWN_MALICIOUS", "MALICIOUS"
            status, risk = "Malicious", "CRITICAL"
        elif vt.get("available") and vt.get("verdict") == "clean":
            verdict, rep, status, risk = "KNOWN_CLEAN", "CLEAN", "Clean", "LOW"
        elif vt.get("available"):
            verdict, rep, status = "UNKNOWN", "UNKNOWN", "Unverified"
            risk = "MEDIUM" if f.get("risky") else "LOW"
        else:
            risky = bool(f.get("risky"))
            verdict = "NOT_SCANNED"
            rep = "SUSPICIOUS" if risky else "CLEAN"
            status = "Suspicious" if risky else "Clean"
            risk = (severity if severity != "SAFE" else "MEDIUM") if risky else "LOW"
        out.append({"filename": a.get("filename", ""),
                    "contentType": a.get("contentType", ""),
                    "sizeLabel": a.get("sizeLabel", "0 B"), "sha256": sha,
                    "sizeBytes": a.get("sizeBytes", 0),
                    "disposition": a.get("disposition", ""),
                    "malformed": bool(a.get("malformed", False)),
                    "risk": risk, "status": status, "reputation": rep,
                    "verdict": verdict,
                    "extension": f.get("extension", ""),
                    "double_extension": bool(f.get("double_extension", False)),
                    "extension_mismatch": bool(f.get("extension_mismatch", False)),
                    "macro_enabled": bool(f.get("macro_enabled", False)),
                    "is_archive": bool(f.get("archive", False)),
                    "vt": vt, "notes": f.get("notes", [])})
    return out


def build_graph(parsed: dict, ip_intel: list[dict], url_intel: list[dict],
                dom_intel: list[dict], attachments: list[dict]) -> dict:
    sender = parsed.get("from", "") or "UNKNOWN"
    nodes: list[dict] = [{"id": f"sender:{sender}", "kind": "sender",
                          "label": sender,
                          "evidence": "From header"}]
    edges: list[dict] = []
    if parsed.get("to"):
        nodes.append({"id": f"rcpt:{parsed['to']}", "kind": "recipient",
                      "label": parsed["to"], "evidence": "To header"})
        edges.append({"from": f"sender:{sender}",
                      "to": f"rcpt:{parsed['to']}", "rel": "sent_to"})
    for d in dom_intel[:15]:
        nodes.append({"id": f"domain:{d['domain']}", "kind": "domain",
                      "label": d["domain"],
                      "evidence": f"reputation={d.get('reputation')}"})
        edges.append({"from": f"sender:{sender}",
                      "to": f"domain:{d['domain']}", "rel": "uses_domain"})
    for u in url_intel[:15]:
        uid = f"url:{u['url'][:120]}"
        nodes.append({"id": uid, "kind": "url", "label": u["url"][:120],
                      "evidence": f"reputation={u.get('reputation')}"})
        edges.append({"from": f"domain:{u.get('domain', '')}", "to": uid,
                      "rel": "redirects_to" if u.get("redirect") else "contained"})
    for p in ip_intel[:15]:
        nodes.append({"id": f"ip:{p['ip']}", "kind": "ip", "label": p["ip"],
                      "evidence": f"abuse={p.get('abuseScore')} "
                      f"country={p.get('country')}"})
        if p.get("asn") and p["asn"] != "UNKNOWN":
            aid = f"asn:{p['asn']}"
            if not any(n["id"] == aid for n in nodes):
                nodes.append({"id": aid, "kind": "asn", "label": p["asn"],
                              "evidence": f"isp={p.get('isp')}"})
            edges.append({"from": f"ip:{p['ip']}", "to": aid,
                          "rel": "hosted_on"})
        if p.get("country") and p["country"] != "UNKNOWN":
            gid = f"geo:{p.get('country')}"
            if not any(n["id"] == gid for n in nodes):
                nodes.append({"id": gid, "kind": "geo",
                              "label": str(p.get("country")),
                              "evidence": "Approximate IP geolocation"})
            edges.append({"from": f"ip:{p['ip']}", "to": gid,
                          "rel": "observed_in"})
    for a in attachments[:10]:
        if a.get("sha256"):
            hid = f"hash:{a['sha256'][:16]}"
            nodes.append({"id": hid, "kind": "hash",
                          "label": a.get("filename", "") or a["sha256"][:16],
                          "evidence": f"sha256={a['sha256'][:32]}..."})
            edges.append({"from": f"sender:{sender}", "to": hid,
                          "rel": "contained"})
    return {"nodes": nodes[:80], "edges": edges[:120]}
