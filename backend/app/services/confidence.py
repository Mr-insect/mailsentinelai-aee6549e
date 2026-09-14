"""SOC scoring breakdown + confidence dimensions."""
from __future__ import annotations


def confidence_dimensions(*, parsed: dict, signals: dict, intel: dict,
                          ai_used: bool, ai_conf: int,
                          geo: dict | None, provider_hits: int,
                          provider_total: int) -> dict:
    parse_ok = 70
    if parsed.get("from") not in ("UNKNOWN", "") and parsed.get("received"):
        parse_ok = 85
    if not parsed.get("received") and not parsed.get("urls"):
        parse_ok = 55
    confirmed = (1 if signals.get("spf_fail") or parsed.get("spfHeader") == "PASS" else 0)
    confirmed += 1 if (intel.get("virustotal_malicious", 0) or 0) > 0 else 0
    confirmed += 1 if (intel.get("max_abuse_score", 0) or 0) >= 50 else 0
    evidence_conf = min(90, 45 + confirmed * 15)
    ti_conf = 30
    if provider_total:
        ti_conf = round(25 + 55 * provider_hits / max(1, provider_total))
    geo_conf = 20
    if geo and geo.get("provider") == "maxmind" and geo.get("accuracy_radius_km"):
        geo_conf = 70
    elif geo and geo.get("country") not in ("UNKNOWN", "", None):
        geo_conf = 55
    final = round(0.35 * evidence_conf + 0.30 * ti_conf
                  + (0.20 * ai_conf if ai_used else 10)
                  + 0.15 * parse_ok)
    return {"parser_confidence": parse_ok, "evidence_confidence": evidence_conf,
            "threat_intel_confidence": min(95, ti_conf),
            "ai_confidence": ai_conf if ai_used else 0,
            "geolocation_confidence": geo_conf,
            "final_verdict_confidence": max(5, min(95, final))}
