"""Sanitized provider-health snapshot (no secrets, ever)."""
from __future__ import annotations

import os


def _state(configured: bool, last_ok: bool | None = None,
           rate_limited: bool = False, error: str = "") -> str:
    if rate_limited:
        return "RATE_LIMITED"
    if error:
        return "ERROR"
    if not configured:
        return "NOT_CONFIGURED"
    if last_ok is False:
        return "ERROR"
    return "CONNECTED"


def provider_health_snapshot(settings, last: dict | None = None) -> dict:
    last = last or {}
    geo_provider = "maxmind" if os.environ.get("MAXMIND_CITY_DB") else \
        ("ip-api" if True else "unavailable")
    return {
        "openai": {"status": _state(bool(settings.OPENAI_API_KEY),
                                    last.get("openai")),
                   "model": settings.OPENAI_MODEL, "configured": bool(settings.OPENAI_API_KEY)},
        "virustotal": {"status": _state(bool(settings.VIRUSTOTAL_API_KEY),
                                        last.get("virustotal"),
                                        bool(last.get("virustotal_rate_limited")),
                                        last.get("virustotal_error", "") or ""),
                       "configured": bool(settings.VIRUSTOTAL_API_KEY)},
        "abuseipdb": {"status": _state(bool(settings.ABUSEIPDB_API_KEY),
                                       last.get("abuseipdb")),
                      "configured": bool(settings.ABUSEIPDB_API_KEY)},
        "google": {"status": _state(bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
                                    last.get("google")),
                   "configured": bool(settings.GOOGLE_SAFE_BROWSING_API_KEY)},
        "geolocation": {"status": "CONNECTED", "provider": geo_provider,
                        "configured": True,
                        "note": "Approximate IP geolocation only."},
    }
