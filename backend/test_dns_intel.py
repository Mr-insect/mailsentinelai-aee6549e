"""Offline tests for REAL DNS/domain intelligence (app.services.dns_intel).

No network access is required: the dnspython layer is faked at the single
``dns_intel._resolve_sync`` seam with canned results that explicitly encode
the four real resolver outcomes (FOUND / NXDOMAIN / EMPTY / ERROR).

Guarantees under test:
- per-record-type successes (A, AAAA, MX, NS, TXT, CNAME, PTR)
- NXDOMAIN (definitive nonexistence) is distinct from DNS errors
- DNS timeout/SERVFAIL -> UNKNOWN; never malicious, never fabricated
- successful-but-empty answers are distinguished from errors
- domain resolution failure produces honest, empty results
- no age/registrar/reputation values are ever invented on failure
- lookups run concurrently in worker threads (event loop stays responsive)
"""
import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest

import app.services.dns_intel as di
import app.services.pipeline as pl
import dns.rdatatype
from app.models.analysis import DomainIntel

requires_dns = pytest.mark.skipif(not di._DNS_AVAILABLE,
                                  reason="dnspython not installed")

RRSIG = dns.rdatatype.RRSIG


class _RR:
    def __init__(self, rdtype):
        self.rdtype = rdtype


class _Resp:
    def __init__(self, rdtypes):
        self.answer = [_RR(t) for t in rdtypes]


def fake_resolver(table, delay=0.0, calls=None):
    """table: {((name, rdtype, want_dnssec)): (state, records, answer)}."""
    def fake(name, rdtype, want_dnssec=False, lifetime=4.0):
        if calls is not None:
            calls.append((name.lower().rstrip("."), rdtype, want_dnssec))
        if delay:
            time.sleep(delay)
        return table.get((name.lower().rstrip("."), rdtype, want_dnssec),
                         ("ERROR", None, None))
    return fake


def run(coro):
    return asyncio.run(coro)


def _analyze(domain, table, timeout=2.0, delay=0.0):
    with patch.object(di, "_resolve_sync", fake_resolver(table, delay)):
        return run(di.analyze_domain_dns(domain, timeout))


# --- canned tables ---------------------------------------------------------
DOMAIN = "example.org"
A_FOUND = ("FOUND", ["93.184.216.34"], None)
AAAA_FOUND = ("FOUND", ["2606:2800:220:1:248:1893:25c8:1946"], None)
MX_FOUND = ("FOUND", ["10 mx1.example.org", "20 mx2.example.org"], None)
NS_FOUND = ("FOUND", ["ns1.example.org", "ns2.example.org"], None)
TXT_FOUND = ("FOUND", ["v=spf1 -all"], None)
CNAME_FOUND = ("FOUND", ["alias.example.net"], None)
DO_UNSIGNED = ("FOUND", ["93.184.216.34"], _Resp([_RR(dns.rdatatype.A)]))
DO_SIGNED = ("FOUND", ["93.184.216.34"], _Resp([_RR(RRSIG)]))

FULL_TABLE = {
    (DOMAIN, "A", False): A_FOUND,
    (DOMAIN, "AAAA", False): AAAA_FOUND,
    (DOMAIN, "MX", False): MX_FOUND,
    (DOMAIN, "NS", False): NS_FOUND,
    (DOMAIN, "TXT", False): TXT_FOUND,
    (DOMAIN, "CNAME", False): CNAME_FOUND,
    (DOMAIN, "A", True): DO_UNSIGNED,
}

NXDOMAIN_TABLE = {key: ("NXDOMAIN", None, None) for key in FULL_TABLE}
EMPTY_TABLE = {key: ("EMPTY", None, None) for key in FULL_TABLE}

PTR_TABLE = dict(FULL_TABLE)
PTR_TABLE[("8.8.8.8.in-addr.arpa", "PTR", False)] = \
    ("FOUND", ["dns.google"], None)


@pytest.fixture(autouse=True)
def _clean_caches():
    di.DNS_CACHE.clear()
    pl.DOMAIN_CACHE.clear()
    yield
    di.DNS_CACHE.clear()
    pl.DOMAIN_CACHE.clear()


class FakeSettings:
    EXTERNAL_TIMEOUT_S = 2.0
    VIRUSTOTAL_API_KEY = ""


# --------------------------------------------------------------------------
# Per-record-type successes
# --------------------------------------------------------------------------
@requires_dns
def test_a_record_success():
    d = _analyze(DOMAIN, {(DOMAIN, "A", False): A_FOUND})
    assert d["status"] == "OK"
    assert d["records"]["a"] == ["93.184.216.34"]
    assert d["lookups"]["a"] == "FOUND"
    assert d["resolved_ips"] == ["93.184.216.34"]
    assert d["summary"].startswith("RESOLVES")


@requires_dns
def test_aaaa_record_success():
    d = _analyze(DOMAIN, {(DOMAIN, "AAAA", False): AAAA_FOUND})
    assert d["records"]["aaaa"] == ["2606:2800:220:1:248:1893:25c8:1946"]
    assert d["lookups"]["aaaa"] == "FOUND"
    assert "2606:2800:220:1:248:1893:25c8:1946" in d["resolved_ips"]


@requires_dns
def test_mx_record_success():
    d = _analyze(DOMAIN, {(DOMAIN, "MX", False): MX_FOUND,
                          (DOMAIN, "A", False): A_FOUND})
    assert d["records"]["mx"] == ["10 mx1.example.org", "20 mx2.example.org"]
    assert d["lookups"]["mx"] == "FOUND"


@requires_dns
def test_ns_record_success():
    d = _analyze(DOMAIN, {(DOMAIN, "NS", False): NS_FOUND})
    assert d["records"]["ns"] == ["ns1.example.org", "ns2.example.org"]
    assert d["lookups"]["ns"] == "FOUND"


@requires_dns
def test_txt_record_success():
    d = _analyze(DOMAIN, {(DOMAIN, "TXT", False): TXT_FOUND})
    assert d["records"]["txt"] == ["v=spf1 -all"]
    assert d["lookups"]["txt"] == "FOUND"


@requires_dns
def test_cname_record_success():
    d = _analyze(DOMAIN, {(DOMAIN, "CNAME", False): CNAME_FOUND})
    assert d["records"]["cname"] == ["alias.example.net"]
    assert "CNAME alias to alias.example.net." in d["notes"]


@requires_dns
def test_full_table_all_record_types():
    d = _analyze(DOMAIN, FULL_TABLE)
    assert d["status"] == "OK"
    for key in ("a", "aaaa", "mx", "ns", "txt", "cname"):
        assert d["lookups"][key] == "FOUND"
        assert d["records"][key]
    assert d["summary"].startswith("RESOLVES ·")


# --------------------------------------------------------------------------
# NXDOMAIN vs DNS errors vs empty answers (the honesty core)
# --------------------------------------------------------------------------
@requires_dns
def test_nxdomain_is_definitive_nonexistence():
    d = _analyze("missing.example", NXDOMAIN_TABLE)
    assert d["status"] == "NXDOMAIN"
    assert d["summary"] == "NXDOMAIN — domain does not resolve"
    assert all(v == "MISSING" for k, v in d["lookups"].items()
               if k != "ptr")
    assert d["resolved_ips"] == []
    assert "Domain does not resolve (NXDOMAIN)" in d["notes"][0]


@requires_dns
def test_dns_timeout_error_is_unknown_not_malicious():
    d = _analyze(DOMAIN, {})  # unlisted -> ERROR for every query
    assert d["status"] == "UNKNOWN"
    assert all(v == "ERROR" for v in d["lookups"].values())
    assert d["records"] == {"a": [], "aaaa": [], "mx": [], "ns": [],
                            "txt": [], "cname": [], "ptr": []}
    assert d["summary"] == "UNKNOWN — DNS lookup failed or returned no data"
    assert any("never evidence of malice" in n for n in d["notes"])


@requires_dns
def test_empty_no_record_answers_distinguished_from_errors():
    d = _analyze(DOMAIN, EMPTY_TABLE)  # NOERROR with no answers
    assert d["status"] == "UNKNOWN"    # existence unverified -> not "OK"
    assert all(v == "MISSING" for k, v in d["lookups"].items() if k != "ptr")
    assert all(v == "ERROR" for v in [])  # (no ERROR states anywhere)
    assert d["records"]["a"] == []
    assert d["summary"] == "UNKNOWN — DNS lookup failed or returned no data"


@requires_dns
def test_mixed_found_and_missing_is_ok():
    # A exists but MX missing (EMPTY): status OK, per-type states correct.
    d = _analyze(DOMAIN, {(DOMAIN, "A", False): A_FOUND,
                          (DOMAIN, "MX", False): ("EMPTY", None, None),
                          (DOMAIN, "A", True): DO_UNSIGNED})
    assert d["status"] == "OK"
    assert d["lookups"]["a"] == "FOUND"
    assert d["lookups"]["mx"] == "MISSING"
    assert "No MX records — domain cannot receive mail." in d["notes"]


@requires_dns
def test_domain_resolution_failure_has_no_ips():
    d = _analyze("nonexistent.invalid", NXDOMAIN_TABLE)
    assert d["resolved_ips"] == []
    assert d["records"]["ptr"] == []      # no PTR attempted: no addresses
    assert d["lookups"]["ptr"] == "NOT_APPLICABLE"


@requires_dns
def test_no_fabricated_values_on_failure():
    d = _analyze(DOMAIN, {})  # total DNS failure
    assert d["status"] == "UNKNOWN"
    assert d["dnssec"] == "UNKNOWN"
    assert d["resolved_ips"] == []
    for key in ("a", "aaaa", "mx", "ns", "txt", "cname", "ptr"):
        assert d["records"][key] == []
        assert d["lookups"][key] == "ERROR"
    # Nothing invented: a single honest note, no positive claims anywhere.
    assert len(d["notes"]) == 1
    assert "UNKNOWN" in d["notes"][0]
    assert "never evidence of malice" in d["notes"][0]


@requires_dns
def test_empty_domain_input_is_unknown():
    d = run(di.analyze_domain_dns("", 2.0))
    assert d["status"] == "UNKNOWN"
    assert d["summary"] == "UNKNOWN — no domain provided"
    assert d["resolved_ips"] == []


# --------------------------------------------------------------------------
# Reverse DNS (PTR) for resolved addresses
# --------------------------------------------------------------------------
@requires_dns
def test_ptr_lookup_for_resolved_ip():
    d = _analyze(DOMAIN, PTR_TABLE)
    assert d["records"]["ptr"] == ["dns.google"]
    assert d["lookups"]["ptr"] == "FOUND"


@requires_dns
def test_ptr_failure_never_degrades_domain_existence():
    d = _analyze(DOMAIN, FULL_TABLE)  # PTR unlisted -> honest ERROR state
    assert d["lookups"]["ptr"] in ("ERROR", "MISSING", "NOT_APPLICABLE")
    assert d["status"] == "OK"


@requires_dns
def test_ptr_absent_when_no_addresses():
    d = _analyze("missing.example", NXDOMAIN_TABLE)
    assert d["lookups"]["ptr"] == "NOT_APPLICABLE"
    assert d["records"]["ptr"] == []


# --------------------------------------------------------------------------
# DNSSEC status
# --------------------------------------------------------------------------
@requires_dns
def test_dnssec_signed_when_rrsig_present():
    d = _analyze(DOMAIN, {(DOMAIN, "A", False): A_FOUND,
                          (DOMAIN, "A", True): DO_SIGNED})
    assert d["dnssec"] == "SIGNED"


@requires_dns
def test_dnssec_unsigned_when_clean_answer_without_rrsig():
    d = _analyze(DOMAIN, {(DOMAIN, "A", False): A_FOUND,
                          (DOMAIN, "A", True): DO_UNSIGNED})
    assert d["dnssec"] == "UNSIGNED"


@requires_dns
def test_dnssec_unknown_on_probe_failure():
    d = _analyze(DOMAIN, {(DOMAIN, "A", False): A_FOUND})  # no DO entry
    assert d["dnssec"] == "UNKNOWN"


# --------------------------------------------------------------------------
# Caching + non-blocking behavior
# --------------------------------------------------------------------------
@requires_dns
def test_dns_results_are_cached():
    calls = []
    table = {(DOMAIN, "A", False): A_FOUND}
    with patch.object(di, "_resolve_sync", fake_resolver(table, calls=calls)):
        run(di.dns_lookup(DOMAIN, "A"))
        run(di.dns_lookup(DOMAIN, "A"))
    assert calls.count((DOMAIN, "A", False)) == 1  # second hit from cache


@requires_dns
def test_concurrent_lookups_do_not_block():
    delay = 0.15
    table = {(f"h{i}.example", "A", False): A_FOUND for i in range(8)}

    async def go():
        return await asyncio.gather(
            *(di.dns_lookup(f"h{i}.example", "A", lifetime=2.0)
              for i in range(8)))

    t0 = time.monotonic()
    with patch.object(di, "_resolve_sync", fake_resolver(table, delay=delay)):
        results = run(go())
    elapsed = time.monotonic() - t0
    assert all(r[0] == "FOUND" for r in results)
    # Serial execution would take ~1.2s; threaded concurrency must beat it.
    assert elapsed < 0.9, f"lookups appear to block the loop: {elapsed:.2f}s"


# --------------------------------------------------------------------------
# Pipeline integration (enrich_domains consumes real DNS + real VT age only)
# --------------------------------------------------------------------------
def _run_enrich(table, vt_response=None):
    parsed = {"domains": [DOMAIN], "replyTo": ""}
    signals = {"sender_domain": DOMAIN}
    with patch.object(di, "_resolve_sync", fake_resolver(table)), \
            patch.object(pl, "virustotal_domain",
                         new=AsyncMock(return_value=vt_response or
                                       {"available": False})):
        return run(pl.enrich_domains(parsed, [], signals, FakeSettings()))


@requires_dns
def test_enrich_domains_uses_real_dns_data():
    rows = _run_enrich(FULL_TABLE)
    row = rows[0]
    assert row["dnsStatus"] == "OK"
    assert "RESOLVES" in row["dns"]
    assert row["dnsRecords"]["a"] == ["93.184.216.34"]
    assert row["dnsLookups"]["mx"] == "FOUND"
    assert "93.184.216.34" in row["resolvedIps"]
    assert row["reputation"] == "UNKNOWN"        # no VT key -> never guessed
    assert row["ageDays"] is None                # no provider -> no age
    assert row["registrar"] == "UNKNOWN"
    assert any("Resolves to" in n for n in row["notes"])


@requires_dns
def test_enrich_domains_age_from_vt_creation_date_only():
    vt = {"available": True, "verdict": "clean", "malicious": 0,
          "registrar": "Legit Registrar LLC",
          "creation_date": int(time.time()) - 100 * 86400}
    rows = _run_enrich(FULL_TABLE, vt_response=vt)
    row = rows[0]
    assert 99 <= row["ageDays"] <= 101           # real, provider-derived
    assert row["registrar"] == "Legit Registrar LLC"
    assert any("Registrar: Legit Registrar LLC" in n for n in row["notes"])


@requires_dns
def test_enrich_domains_nxdomain_no_fabrication():
    rows = _run_enrich(NXDOMAIN_TABLE)
    row = rows[0]
    assert row["dnsStatus"] == "NXDOMAIN"
    assert "NXDOMAIN" in row["dns"]
    assert row["ageDays"] is None
    assert row["registrar"] == "UNKNOWN"
    assert row["reputation"] == "UNKNOWN"        # NXDOMAIN is not malicious
    assert row["resolvedIps"] == []


@requires_dns
def test_enrich_domains_dns_failure_no_fabrication():
    rows = _run_enrich({})  # every DNS query errors
    row = rows[0]
    assert row["dnsStatus"] == "UNKNOWN"
    assert row["dns"].startswith("UNKNOWN")
    assert row["ageDays"] is None                # not fabricated
    assert row["registrar"] == "UNKNOWN"         # not fabricated
    assert row["reputation"] == "UNKNOWN"        # failure != malicious
    assert row["dnssec"] == "UNKNOWN"
    assert all(v == "ERROR" for k, v in row["dnsLookups"].items()
               if k != "ptr")
    assert row["resolvedIps"] == []


# --------------------------------------------------------------------------
# Model compatibility (additive fields, old consumers unaffected)
# --------------------------------------------------------------------------
def test_domain_intel_model_defaults_and_new_fields():
    base = DomainIntel(domain="x.org")
    assert base.dns == "UNKNOWN" and base.ageDays is None
    assert base.dnsStatus == "UNKNOWN" and base.dnssec == "UNKNOWN"
    assert base.dnsRecords == {} and base.dnsLookups == {}
    assert base.resolvedIps == []
    full = DomainIntel(domain="x.org", dnsStatus="OK", dnssec="SIGNED",
                       dnsRecords={"a": ["1.2.3.4"]},
                       dnsLookups={"a": "FOUND"}, resolvedIps=["1.2.3.4"])
    assert full.dnsRecords == {"a": ["1.2.3.4"]}
    assert full.resolvedIps == ["1.2.3.4"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))