"""Domain intelligence: local heuristics + live VT reputation + safe DNS/RDAP hints."""
from __future__ import annotations

import re
import socket

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
              "rb.gy", "ow.ly", "buff.ly", "bitly.com"}
SUSP_TLD = (".zip", ".top", ".xyz", ".click", ".link", ".tk", ".ru", ".cn",
            ".gq", ".rest", ".mov", ".country", ".stream")
BRANDS = ("microsoft", "office365", "paypal", "google", "apple", "amazon",
          "netflix", "dhl", "bank", "university", "outlook", "sharepoint")


def registrable_domain(d: str) -> str:
    d = (d or "").lower().strip().rstrip(".")
    parts = d.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return d


def analyze_domain_local(domain: str, sender_domain: str = "",
                         reply_domain: str = "") -> dict:
    d = (domain or "").lower().strip()
    reg = registrable_domain(d)
    sub_parts = d.split(".")
    depth = max(0, len(sub_parts) - 2)
    puny = "xn--" in d
    short = d in SHORTENERS or d.endswith(tuple("." + s for s in SHORTENERS))
    tld_bad = any(d.endswith(t) for t in SUSP_TLD)
    look, brand = False, None
    for b in BRANDS:
        if b in d and not d.endswith(f"{b}.com") and not d.endswith(".edu"):
            look, brand = True, b
            break
    hyphen_trick = bool(re.search(r"-(secure|login|verify|account|support|update)\b", d))
    mismatch_sender = bool(sender_domain) and reg != registrable_domain(sender_domain) and d == sender_domain
    reply_mismatch = bool(reply_domain) and registrable_domain(reply_domain) != reg
    notes = []
    if puny:
        notes.append("Punycode / IDN homograph risk.")
    if short:
        notes.append("URL shortener — hides final destination.")
    if tld_bad:
        notes.append("Suspicious TLD frequently abused.")
    if depth >= 2:
        notes.append(f"Unusual subdomain depth ({depth}).")
    if look:
        notes.append(f"Possible brand impersonation ({brand}).")
    if hyphen_trick:
        notes.append("Hyphenated security keyword (login/verify).")
    return {"domain": d, "registrable": reg,
            "subdomain": d[: -len(reg) - 1] if d != reg and d.endswith(reg) else "",
            "depth": depth, "punycode": puny, "shortener": short,
            "suspicious_tld": tld_bad, "lookalike": look or hyphen_trick,
            "lookalike_of": brand, "sender_mismatch": mismatch_sender,
            "reply_mismatch": reply_mismatch, "notes": notes}
