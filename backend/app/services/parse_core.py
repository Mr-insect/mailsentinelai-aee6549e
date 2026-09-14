"""Core parse routine returning ParsedEmail-compatible dict."""
from __future__ import annotations

import email
import email.policy
import hashlib
import re

import email.utils

from .email_parser import EmailParseError, is_public_ip
from .email_parser import EMAIL_RE, HREF_RE, IP_RE, URL_RE
from .parse_helpers import _addr, _auth, _html_to_text, _size


def parse_eml(raw: bytes) -> dict:
    if not raw or len(raw) > 8 * 1024 * 1024:
        raise EmailParseError("Invalid email file. Please upload a valid .EML file.")
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:
        raise EmailParseError("Invalid email file.") from exc

    headers = [{"name": k, "value": str(v)} for k, v in msg.items()]
    names = {h["name"].lower() for h in headers}
    if not names.intersection({"from", "to", "subject", "message-id", "received", "date"}):
        raise EmailParseError("Invalid email file. Please upload a valid .EML file.")

    def get(n: str) -> str:
        v = msg.get(n, "")
        return str(v) if v else ""

    def get_all(n: str) -> list[str]:
        return [str(v) for v in msg.get_all(n, [])]

    text_body, html_body = "", ""
    attachments: list[dict] = []
    warnings: list[str] = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue
                ctype = (part.get_content_type() or "").lower()
                disp = part.get_content_disposition() or ""
                fname = part.get_filename() or ""
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:
                    warnings.append("Could not decode a MIME part.")
                    continue
                if fname or disp == "attachment":
                    attachments.append({
                        "filename": fname or "unnamed-attachment",
                        "contentType": ctype or "application/octet-stream",
                        "sizeLabel": _size(len(payload)),
                        "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
                        "sizeBytes": len(payload),
                        "disposition": disp or "attachment",
                        "malformed": False,
                    })
                elif ctype == "text/plain" and not text_body:
                    text_body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                elif ctype == "text/html" and not html_body:
                    html_body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        else:
            try:
                p = msg.get_payload(decode=True)
                dec = p.decode(msg.get_content_charset() or "utf-8", errors="replace") if isinstance(p, bytes) else str(msg.get_payload() or "")
            except Exception:
                dec = str(msg.get_payload() or "")
            if "html" in (msg.get_content_type() or "").lower():
                html_body = dec
            else:
                text_body = dec
    except EmailParseError:
        raise
    except Exception as exc:
        raise EmailParseError("Analysis failed.") from exc

    body = text_body or (_html_to_text(html_body) if html_body else "")
    block = "\n".join(f"{h['name']}: {h['value']}" for h in headers)
    received = get_all("Received")
    hrefs = HREF_RE.findall(html_body or "")
    urls = sorted({u.rstrip(".,;)") for u in URL_RE.findall(" ".join([text_body, html_body or "", " ".join(hrefs)]))})
    ips = sorted({ip for ip in IP_RE.findall(" ".join([*received, block])) if is_public_ip(ip)})
    fa, disp = _addr(get("From"))
    ra, _ = _addr(get("Reply-To"))
    pa, _ = _addr(get("Return-Path"))
    ta, _ = _addr(get("To"))
    cc = [a for _, a in email.utils.getaddresses([get("Cc")]) if "@" in a]
    bem = [e.lower() for e in EMAIL_RE.findall(body or "")]
    emails = sorted({e.lower() for e in [fa, ra, pa, *cc, ta, *bem] if e and "@" in e})

    def durl(u: str) -> str:
        m = re.match(r"https?://([^/?#:]+)", u, re.IGNORECASE)
        return m.group(1).lower() if m else ""

    domains = sorted({d.lower() for d in ([durl(u) for u in urls] + [e.split("@")[1] for e in emails if "@" in e]) if d})
    authr = " ".join([*get_all("Authentication-Results"), *get_all("ARC-Authentication-Results")])
    spfd = get("Received-SPF")
    dkim_sig = bool(get("DKIM-Signature"))
    if authr:
        spf = _auth(authr, "spf")
    elif spfd:
        spf = "PASS" if re.search(r"pass", spfd, re.IGNORECASE) else \
              ("FAIL" if re.search(r"\b(fail|softfail|reject)\b", spfd, re.IGNORECASE) else
               ("NONE" if re.search(r"\bnone\b", spfd, re.IGNORECASE) else "UNKNOWN"))
    else:
        spf = "UNKNOWN"

    parsed = {
        "from": fa or "UNKNOWN", "displayName": disp or "UNKNOWN",
        "to": ta or "UNKNOWN", "cc": cc, "replyTo": ra, "returnPath": pa,
        "subject": get("Subject") or "(no subject)", "date": get("Date") or "UNKNOWN",
        "messageId": get("Message-ID") or "UNKNOWN", "received": received,
        "headers": headers[:200], "rawHeaders": block[:8000],
        "body": body[:20000], "textBody": text_body[:20000], "htmlBody": "",
        "urls": urls[:25], "ips": ips[:25], "emails": emails[:50], "domains": domains[:25],
        "attachments": attachments[:10], "spfHeader": spf,
        "dkimHeader": _auth(authr, "dkim") if authr else ("NONE" if not dkim_sig else "SUSPICIOUS"),
        "dmarcHeader": _auth(authr, "dmarc") if authr else "UNKNOWN",
        "parseWarnings": sorted(set(warnings)),
    }
    return {"parsed": parsed, "message_sha256": hashlib.sha256(raw).hexdigest()}
