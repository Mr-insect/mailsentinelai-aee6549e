"""Server-side EML parsing. Untrusted input: decode only, never execute."""
from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import re

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s\"'<>)\\\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HREF_RE = re.compile(r"(?:href|src)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)


class EmailParseError(ValueError):
    pass


def is_public_ip(ip: str) -> bool:
    if ip.startswith(("10.", "127.", "192.168.", "0.", "255.")):
        return False
    if ip.startswith("172."):
        try:
            if 16 <= int(ip.split(".")[1]) <= 31:
                return False
        except ValueError:
            return False
    return True
