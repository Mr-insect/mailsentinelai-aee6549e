"""Smoke tests: parsing, scoring, sanitization. No network, no keys."""
from app.services.heuristics import heuristic_signals, sanitize_for_ai
from app.services.parse_core import parse_eml
from app.services.scoring import fuse_score, severity_for

SAMPLE = b"""From: a@evil.top\r\nTo: v@univ.edu\r\nSubject: hi\r\nMessage-ID: <1@x>\r\nDate: Tue, 9 Sep 2026 10:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nVerify your account immediately http://evil.top/login\r\n"""


def test_parse_extracts_indicators():
    out = parse_eml(SAMPLE)
    assert out["parsed"]["from"] == "a@evil.top"
    assert any("evil.top" in u for u in out["parsed"]["urls"])
    assert len(out["message_sha256"]) == 64


def test_signals_and_score():
    out = parse_eml(SAMPLE)
    sig = heuristic_signals(out["parsed"])
    assert sig["has_cred"] and sig["has_urgency"]
    score, indicators, threat = fuse_score(sig, {"virustotal_malicious": 0,
                                                 "safebrowsing_flagged": 0,
                                                 "max_abuse_score": 0}, None, False)
    assert score > 0 and indicators and threat


def test_sanitize_drops_raw_content():
    out = parse_eml(SAMPLE)
    ev = sanitize_for_ai(out["parsed"], {"x": 1}, 100, 5)
    assert "rawHeaders" not in ev and "htmlBody" not in ev
    assert len(ev["body_excerpt"]) <= 100


def test_severity_bands():
    assert severity_for(90) == "CRITICAL" and severity_for(0) == "SAFE"
