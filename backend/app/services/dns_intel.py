"""Real DNS intelligence for domains (dnspython).

Replaces the previous hardcoded ``"dns": "UNKNOWN"`` placeholder with actual
resolution data: A/AAAA, MX, NS, TXT, CNAME, PTR (reverse DNS for resolved
addresses), DNSSEC signing status and domain existence.

Honesty rules (this module never fabricates):
- A successful query with zero answers is EMPTY (name exists, no records).
- NXDOMAIN is a definitive, authoritative "does not exist".
- Timeouts / SERVFAIL / any transport failure are ERROR -> results fall back
  to UNKNOWN; a lookup failure is NEVER treated as malicious and never
  converted into a positive claim (no records, no age, no registrar).
- Registration age/registrar are NOT guessed here: they only come from a
  configured provider (VirusTotal) in pipeline.enrich_domains; without one
  they stay UNKNOWN/None.
- Every query runs in a worker thread (asyncio.to_thread) with explicit
  timeout/lifetime bounds; results are cached in DNS_CACHE to bound load.
"""
from __future__ import annotations

import asyncio
import logging

from .cache import DNS_CACHE, norm_domain

log = logging.getLogger("mailsentinel.dns_intel")

try:
    import dns.exception
    import dns.rdatatype
    import dns.resolver
    import dns.reversename
    _DNS_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    _DNS_AVAILABLE = False

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
_RESOLVER = None
_SERVER_TIMEOUT_S = 2.0


def _get_resolver():
    global _RESOLVER
    if _RESOLVER is None:
        r = dns.resolver.Resolver(configure=True)
        r.timeout = _SERVER_TIMEOUT_S
        r.lifetime = _SERVER_TIMEOUT_S * 2
        _RESOLVER = r
    return _RESOLVER


def _format_records(answer, rdtype: str) -> list[str]:
    """Deterministic, normalized record strings (names: lowercase, no dot)."""
    recs: list[str] = []
    for rdata in answer:
        try:
            if rdtype in ("A", "AAAA"):
                recs.append(str(rdata))
            elif rdtype == "MX":
                recs.append(f"{int(rdata.preference)} "
                            f"{str(rdata.exchange).rstrip('.').lower()}")
            elif rdtype in ("NS", "PTR", "CNAME"):
                recs.append(str(rdata).rstrip(".").lower())
            elif rdtype == "TXT":
                strings = getattr(rdata, "strings", None) or ()
                recs.append(b"".join(bytes(s) for s in strings)
                            .decode("utf-8", "replace"))
        except Exception:  # a single malformed rdata must not kill the lookup
            continue
    return sorted(set(recs))


def _resolve_sync(name: str, rdtype: str, want_dnssec: bool = False,
                  lifetime: float = 4.0):
    """Low-level query -> (state, records|None, answer|None).

    state: FOUND (answer with records) | NXDOMAIN (definitive nonexistence) |
    EMPTY (NOERROR, no answers) | ERROR (timeout/SERVFAIL/unavailable).
    Cached in DNS_CACHE; never raises.
    """
    if not _DNS_AVAILABLE:  # pragma: no cover - optional dependency
        return "ERROR", None, None
    key = f"dns:{name}:{rdtype}" + (":do" if want_dnssec else "")
    cached = DNS_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        answer = _get_resolver().resolve(name, rdtype,
                                         want_dnssec=want_dnssec,
                                         lifetime=lifetime)
    except dns.resolver.NXDOMAIN:
        out = ("NXDOMAIN", None, None)
    except dns.resolver.NoAnswer:
        out = ("EMPTY", None, None)
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        out = ("ERROR", None, None)
    except dns.exception.DNSException:
        out = ("ERROR", None, None)
    except Exception as exc:
        log.debug("dns query %s %s failed: %s", name, rdtype,
                  type(exc).__name__)
        out = ("ERROR", None, None)
    else:
        out = ("FOUND", _format_records(answer, rdtype), answer)
    DNS_CACHE.set(key, out)
    return out


async def dns_lookup(name: str, rdtype: str, want_dnssec: bool = False,
                     lifetime: float = 4.0):
    """Async DNS query in a worker thread. Never raises."""
    return await asyncio.to_thread(_resolve_sync, name, rdtype,
                                   want_dnssec, lifetime)


def _reverse_name(ip: str) -> str:
    try:
        return dns.reversename.from_address(ip).to_text().rstrip(".")
    except Exception:
        return ""


def _has_rrsig(answer) -> bool:
    """DNSSEC probe: RRSIG records present in the answer (DO bit was set)."""
    try:
        return any(rr.rdtype == dns.rdatatype.RRSIG
                   for rr in answer.response.answer)
    except Exception:
        return False


def _summarize(status: str, records: dict, has_addresses: bool) -> str:
    """Human-readable summary for the existing ``dns`` field (frontend shows
    this string verbatim). Honest for every state."""
    if status == "NXDOMAIN":
        return "NXDOMAIN — domain does not resolve"
    if status == "UNKNOWN":
        return "UNKNOWN — DNS lookup failed or returned no data"
    labels = (("A", "a"), ("AAAA", "aaaa"), ("MX", "mx"), ("NS", "ns"),
              ("TXT", "txt"), ("CNAME", "cname"))
    parts = [f"{label}:{len(records[key])}" for label, key in labels
             if records.get(key)]
    prefix = "RESOLVES" if has_addresses else "NO A/AAAA"
    if parts:
        return f"{prefix} · " + " · ".join(parts)
    return prefix if has_addresses else "NO DNS RECORDS"


async def analyze_domain_dns(domain: str, timeout_s: float = 8.0) -> dict:
    """Full DNS intelligence for one domain. Never raises; failures degrade
    to UNKNOWN and never produce fabricated records, age or reputation.

    Returns {"domain", "status", "dnssec", "records", "lookups",
             "resolved_ips", "summary", "notes"}.
    """
    domain = norm_domain(domain)
    lifetime = max(1.0, min(float(timeout_s or 8.0), 6.0))
    records: dict[str, list[str]] = {k.lower(): [] for k in RECORD_TYPES}
    lookups: dict[str, str] = {k.lower(): "ERROR" for k in RECORD_TYPES}

    if not domain or not _DNS_AVAILABLE:
        summary = "UNKNOWN — no domain provided" if not domain else \
            "UNKNOWN — DNS resolver unavailable"
        return {"domain": domain, "status": "UNKNOWN", "dnssec": "UNKNOWN",
                "records": records, "lookups": lookups, "resolved_ips": [],
                "summary": summary,
                "notes": ["DNS intelligence unavailable (no data, never guessed)."]}

    # All record types + the DNSSEC probe run concurrently in worker threads.
    results = await asyncio.gather(
        *(dns_lookup(domain, rdtype, lifetime=lifetime) for rdtype in RECORD_TYPES),
        dns_lookup(domain, "A", want_dnssec=True, lifetime=lifetime))

    states = {}
    for rdtype, (state, recs, _ans) in zip(RECORD_TYPES, results):
        key = rdtype.lower()
        states[key] = state
        lookups[key] = "FOUND" if state == "FOUND" else \
            ("MISSING" if state in ("NXDOMAIN", "EMPTY") else "ERROR")
        if state == "FOUND" and recs:
            records[key] = recs

    _do_state, _do_recs, do_answer = results[-1]
    if _do_state in ("FOUND", "EMPTY"):
        dnssec = "SIGNED" if _has_rrsig(do_answer) else "UNSIGNED"
    else:
        dnssec = "UNKNOWN"

    resolved_ips = sorted(set(records["a"]) | set(records["aaaa"]))[:25]
    if any(v == "FOUND" for v in states.values()):
        status = "OK"
    elif any(v == "NXDOMAIN" for v in states.values()):
        status = "NXDOMAIN"
    else:
        status = "UNKNOWN"  # all errors, or all empty: existence unverified

    # Reverse DNS for a bounded number of resolved addresses.
    ptr_states: list[str] = []
    for ip in resolved_ips[:2]:
        rev = _reverse_name(ip)
        if not rev:
            continue
        p_state, p_recs, _p = await dns_lookup(rev, "PTR", lifetime=lifetime)
        ptr_states.append("FOUND" if p_state == "FOUND" else
                          ("MISSING" if p_state in ("NXDOMAIN", "EMPTY")
                           else "ERROR"))
        if p_state == "FOUND" and p_recs:
            records["ptr"] = sorted(set(records["ptr"]) | set(p_recs))[:10]
    lookups["ptr"] = ("FOUND" if "FOUND" in ptr_states else
                      ("ERROR" if "ERROR" in ptr_states else
                       ("MISSING" if ptr_states else "NOT_APPLICABLE")))

    # Honest notes: failures never become positive claims.
    notes: list[str] = []
    if status == "NXDOMAIN":
        notes.append("Domain does not resolve (NXDOMAIN) — no DNS records exist.")
    elif status == "UNKNOWN":
        notes.append("DNS lookups failed or returned no data — domain DNS "
                     "status UNKNOWN (failure is not evidence of malice).")
    else:
        if resolved_ips:
            notes.append(f"Resolves to {len(resolved_ips)} address(es).")
        if states["mx"] in ("NXDOMAIN", "EMPTY"):
            notes.append("No MX records — domain cannot receive mail.")
        if records["cname"]:
            notes.append(f"CNAME alias to {records['cname'][0]}.")
        if dnssec == "SIGNED":
            notes.append("DNSSEC: zone is signed.")
        elif dnssec == "UNSIGNED":
            notes.append("DNSSEC: zone is not signed.")

    return {"domain": domain, "status": status, "dnssec": dnssec,
            "records": records, "lookups": lookups,
            "resolved_ips": resolved_ips,
            "summary": _summarize(status, records, bool(resolved_ips)),
            "notes": notes}