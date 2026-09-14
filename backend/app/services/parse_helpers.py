import email.utils
import hashlib
import html as html_lib
import re

from .email_parser import (
    EMAIL_RE,
    HREF_RE,
    IP_RE,
    URL_RE,
    EmailParseError,
    is_public_ip,
)


def _addr(value: str):
    if not value:
        return "", ""
    name, addr = email.utils.parseaddr(value)
    return addr.strip(), name.strip().strip('"')


def _auth(results: str, key: str) -> str:
    m = re.search(rf"{key}\s*=\s*([a-z]+)", results, re.IGNORECASE)
    if not m:
        return "UNKNOWN"
    v = m.group(1).lower()
    if v == "pass":
        return "PASS"
    if v in ("fail", "softfail", "permerror", "reject"):
        return "FAIL"
    if v == "none":
        return "NONE"
    if v == "neutral":
        return "SUSPICIOUS"
    return "UNKNOWN"


def _html_to_text(h: str) -> str:
    t = re.sub(r"<script[\s\S]*?</script>", " ", h, flags=re.IGNORECASE)
    t = re.sub(r"<style[\s\S]*?</style>", " ", t, flags=re.IGNORECASE)
    t = re.sub(r"<br\s*/?>", "\n", t, flags=re.IGNORECASE)
    t = re.sub(r"</(p|div|tr|li|h[1-6])>", "\n", t, flags=re.IGNORECASE)
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"[ \t]{2,}", " ", html_lib.unescape(t)).strip()


def _size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"
