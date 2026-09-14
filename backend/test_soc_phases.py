"""Phase 20 SOC tests: fixtures + honesty rules. Offline; no keys, no network.

Each scenario proves that missing/incomplete evidence degrades to
UNKNOWN/UNAVAILABLE and never produces fabricated intelligence.
"""
import asyncio
import time
from unittest.mock import AsyncMock, patch

from app.services.ai_analyzer import ai_verdict
from app.services.cache import TTLCache
from app.services.domain_intel import analyze_domain_local
from app.services.enrich import enrich_ips, enrich_urls, risk_of
from app.services.evidence import make_evidence, unavailable_evidence
from app.services.forensics import (attachment_forensics, auth_forensics,
                                    parse_received_hops)
from app.services.geo_providers import is_routable_public_ip
from app.services.heuristics import heuristic_signals
from app.services.parse_core import parse_eml
from app.services.url_analysis import analyze_url_local


class FakeSettings:
    VIRUSTOTAL_API_KEY = ""
    ABUSEIPDB_API_KEY = ""
    GOOGLE_SAFE_BROWSING_API_KEY = ""
    EXTERNAL_TIMEOUT_S = 0.01
    AI_TIMEOUT_S = 0.01
    AI_MAX_BODY_CHARS = 100
    AI_MAX_URLS = 5
    MAX_EML_BYTES = 8 * 1024 * 1024


LEGIT = b"""From: billing@acme-corp.com\r
Reply-To: billing@acme-corp.com\r
Return-Path: <billing@acme-corp.com>\r
To: staff@example.org\r
Subject: Invoice #2214\r
Message-ID: <2214@mail.acme-corp.com>\r
Date: Mon, 9 Sep 2026 10:00:00 +0000\r
Received: from mail.acme-corp.com (203.0.113.10) by mx.example.org; Mon, 9 Sep 2026 10:01:00 +0000\r
DKIM-Signature: v=1; d=acme-corp.com; s=s1\r
Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.d=acme-corp.com; dmarc=pass header.from=acme-corp.com\r
Content-Type: text/plain\r
\r
Hi, please find the invoice attached. Best, Billing\r
"""

SPF_FAIL = b"""From: a@evil.top\r
To: v@univ.edu\r
Subject: hi\r
Received-SPF: fail (domain does not designate permitted sender)\r
Authentication-Results: mx.univ.edu; spf=fail smtp.mailfrom=evil.top\r
Content-Type: text/plain\r
\r
click http://evil.top/login\r
"""

DKIM_FAIL = b"""From: a@evil.top\r
To: v@univ.edu\r
Subject: hi\r
DKIM-Signature: v=1; d=evil.top; s=s1\r
Authentication-Results: mx.univ.edu; dkim=fail header.d=evil.top\r
Content-Type: text/plain\r
\r
hi\r
"""
DMARC_FAIL = b"""From: a@evil.top\r
To: v@univ.edu\r
Subject: hi\r
Authentication-Results: mx.univ.edu; spf=pass smtp.mailfrom=evil.top; dkim=pass header.d=evil.top; dmarc=fail header.from=evil.top\r
Content-Type: text/plain\r
\r
hi\r
"""

REPLY_MISMATCH = b"""From: a@evil.top\r
Reply-To: collector@evil-cc.top\r
To: v@univ.edu\r
Subject: re\r
Content-Type: text/plain\r
\r
hi\r
"""

LOOKALIKE = b"""From: noreply@micr0soft-secure.top\r
To: v@univ.edu\r
Subject: account\r
Content-Type: text/plain\r
\r
verify now http://micr0soft-secure.top/login\r
"""

MALICIOUS_URL_EML = b"""From: a@sender.com\r
To: v@univ.edu\r
Subject: fwd\r
Content-Type: text/plain\r
\r
http://evil.example/panel?token=1\r
"""

SUSPICIOUS_ATTACH = b"""From: a@sender.com\r
To: v@univ.edu\r
Subject: invoice\r
Content-Type: multipart/mixed; boundary="bb"\r
\r
--bb\r
Content-Type: application/octet-stream\r
Content-Disposition: attachment; filename="invoice.pdf.exe"\r
\r
MZ..........\r
--bb--\r
"""

PRIVATE_IP = b"""From: a@sender.com\r
To: v@univ.edu\r
Subject: p\r
Received: from localhost (127.0.0.1) by mx; Mon, 9 Sep 2026 10:00:00 +0000\r
Received: from 192.168.1.5 by mx2; Mon, 9 Sep 2026 10:01:00 +0000\r
Content-Type: text/plain\r
\r
hi\r
"""

NO_TIMESTAMP = b"""From: a@sender.com\r
To: v@univ.edu\r
Subject: x\r
Received: from mail.sender.com by mx.example.org\r
Content-Type: text/plain\r
\r
hi\r
"""

MULTI_HOP = b"""From: a@sender.com\r
To: v@univ.edu\r
Subject: h\r
Received: from mx2.example.org (198.51.100.9) by mail.example.org; Tue, 10 Sep 2026 09:00:00 +0000\r
Received: from mail.sender.com (203.0.113.5) by mx2.example.org; Tue, 10 Sep 2026 08:59:00 +0000\r
Content-Type: text/plain\r
\r
hi\r
"""


def run(coro):
    return asyncio.run(coro)
def test_legit_email_all_pass():
    p = parse_eml(LEGIT)["parsed"]
    assert p["spfHeader"] == "PASS"
    assert p["dkimHeader"] == "PASS"
    assert p["dmarcHeader"] == "PASS"
    fx = auth_forensics(p)
    assert fx["alignment"] == "PASS"


def test_spf_failure_confirmed_not_inferred():
    p = parse_eml(SPF_FAIL)["parsed"]
    assert p["spfHeader"] == "FAIL"
    ev = make_evidence(category="authentication", title="SPF FAIL",
                       severity="HIGH", confidence=90,
                       observed_value="FAIL", source="Authentication-Results",
                       provider="header", evidence="spf=fail",
                       status="confirmed", observed_vs_inferred="observed")
    assert ev["status"] == "confirmed" and ev["observed_vs_inferred"] == "observed"


def test_dkim_failure():
    p = parse_eml(DKIM_FAIL)["parsed"]
    assert p["dkimHeader"] == "FAIL"


def test_dmarc_failure():
    p = parse_eml(DMARC_FAIL)["parsed"]
    assert p["dmarcHeader"] == "FAIL"


def test_reply_to_mismatch():
    p = parse_eml(REPLY_MISMATCH)["parsed"]
    assert p["replyTo"].lower() != p["from"].lower()
    fx = auth_forensics(p)
    assert fx["reply_suspicious"] is True


def test_lookalike_domain():
    d = analyze_domain_local("micr0soft-secure.top", "micr0soft-secure.top", "")
    assert d["lookalike"] is True
    sig = heuristic_signals(parse_eml(LOOKALIKE)["parsed"])
    assert sig["domain_anomaly"] is True


def test_unknown_url_never_shown_clean():
    a = analyze_url_local("http://evil.example/panel?token=1")
    assert a["indicators"]
    assert risk_of("UNKNOWN") == "MEDIUM"


def test_unknown_url_without_providers():
    p = parse_eml(MALICIOUS_URL_EML)["parsed"]
    rows, vt_mal, sb_n = run(enrich_urls(p, FakeSettings()))
    assert len(rows) == 1
    assert rows[0]["reputation"] == "UNKNOWN"
    assert vt_mal == 0
    assert "Unknown is NOT clean" in " ".join(rows[0]["notes"])


def test_suspicious_attachment_forensics():
    p = parse_eml(SUSPICIOUS_ATTACH)["parsed"]
    fore = attachment_forensics(p["attachments"])
    assert fore and fore[0]["double_extension"] is True
    assert fore[0]["risky"] is True


def test_private_ips_not_extracted():
    p = parse_eml(PRIVATE_IP)["parsed"]
    assert "127.0.0.1" not in p["ips"]
    assert "192.168.1.5" not in p["ips"]
    assert is_routable_public_ip("10.0.0.1") is False
    assert is_routable_public_ip("169.254.1.1") is False


def test_unknown_ip_never_clean():
    p = {"urls": [], "ips": ["8.8.8.8"]}
    intel, geos, max_abuse = run(enrich_ips(p, FakeSettings()))
    assert len(intel) == 1
    assert intel[0]["reputation"] != "MALICIOUS"
    assert max_abuse == 0


def test_missing_timestamps_are_unknown():
    p = parse_eml(NO_TIMESTAMP)["parsed"]
    hops = parse_received_hops(p["received"])
    assert hops and hops[0]["timestamp"] is None


def test_multiple_received_hops():
    p = parse_eml(MULTI_HOP)["parsed"]
    hops = parse_received_hops(p["received"])
    assert len(hops) == 2
    assert hops[0]["timestamp"] is not None
    assert hops[0]["ip"] == "203.0.113.5"


def test_cache_ttl():
    c = TTLCache(default_ttl_s=0.05)
    c.set("a", {"v": 1})
    assert c.get("a") == {"v": 1}
    time.sleep(0.08)
    assert c.get("a") is None


class _FakeResp:
    status_code = 200

    def json(self):
        return {"choices": [{"message": {"content": "not-json${"}}]}


class _FakeClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **k):
        return _FakeResp()
def test_ai_unavailable_no_fabrication():
    verdict, used = run(ai_verdict({"x": 1}, "", "gpt-4o-mini", 1.0))
    assert used is False
    assert verdict.classification.startswith("UNKNOWN")


def test_ai_invalid_json_falls_back():
    with patch("app.services.ai_analyzer.httpx.AsyncClient", _FakeClient):
        verdict, used = run(ai_verdict({"x": 1}, "fake-key", "gpt-4o-mini", 1.0))
    assert used is False
    assert verdict.confidence < 60


def test_provider_rate_limit_degrades_to_unknown():
    p = {"urls": ["http://rate.example/x"], "ips": []}
    with patch("app.services.enrich.virustotal_url",
               new=AsyncMock(return_value={"available": False, "status": 429,
                                           "reason": "rate_limited"})):
        rows, vt_mal, _ = run(enrich_urls(p, FakeSettings()))
    assert vt_mal == 0
    assert rows[0]["reputation"] == "UNKNOWN"


def test_provider_timeout_degrades_to_unknown():
    p = {"urls": [], "ips": ["8.8.4.4"]}
    with patch("app.services.enrich.abuseipdb_check",
               new=AsyncMock(return_value={"available": False})):
        intel, _, _ = run(enrich_ips(p, FakeSettings()))
    assert intel[0]["reputation"] != "MALICIOUS"


def test_unavailable_evidence_tracking():
    e = unavailable_evidence("threat-intel", "VirusTotal unavailable",
                             "virustotal", "not configured")
    assert e["status"] == "unavailable"
    assert e["observed_vs_inferred"] == "observed"


def test_no_fabricated_attack_chain_without_evidence():
    """Fusions without evidence must not create malicious stages."""
    sig = {"spf_fail": False, "dkim_fail": False, "dmarc_fail": False,
           "has_cred": False, "has_urgency": False, "risky_attachments": [],
           "suspicious_tld_urls": [], "shortener_urls": [], "http_urls": [],
           "lookalike": (False, None), "reply_mismatch": False,
           "domain_anomaly": False}
    from app.services.scoring import fuse_score, severity_for
    score, indicators, threat = fuse_score(
        sig, {"virustotal_malicious": 0, "safebrowsing_flagged": 0,
              "max_abuse_score": 0, "attachment_malicious": 0}, None, False)
    assert threat in ("Legitimate Email", "Likely Safe")
    assert score < 31
    assert severity_for(score) in ("SAFE", "LOW")


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))