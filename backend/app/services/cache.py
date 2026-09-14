"""Safe TTL cache + per-investigation deduplication for provider results.

Cache keys: normalized IP / URL / domain / file SHA-256.
No email bodies or keys are cached. In-memory only (MVP).
"""
from __future__ import annotations

import time


class TTLCache:
    def __init__(self, default_ttl_s: float = 3600.0, max_entries: int = 2000):
        self._store: dict[str, tuple[float, object]] = {}
        self._ttl = default_ttl_s
        self._max = max_entries

    def get(self, key: str):
        item = self._store.get(key)
        if not item:
            return None
        exp, val = item
        if time.monotonic() > exp:
            self._store.pop(key, None)
            return None
        return val

    def set(self, key: str, value: object, ttl_s: float | None = None):
        if len(self._store) >= self._max:
            # evict oldest expiry first (simple)
            oldest = min(self._store.items(), key=lambda kv: kv[1][0])[0]
            self._store.pop(oldest, None)
        self._store[key] = (time.monotonic() + (ttl_s if ttl_s is not None else self._ttl), value)

    def clear(self):
        self._store.clear()


# Module-level shared caches (process-local, safe for MVP).
URL_CACHE = TTLCache(default_ttl_s=6 * 3600)
IP_CACHE = TTLCache(default_ttl_s=6 * 3600)
DOMAIN_CACHE = TTLCache(default_ttl_s=12 * 3600)
HASH_CACHE = TTLCache(default_ttl_s=24 * 3600)
GEO_CACHE = TTLCache(default_ttl_s=24 * 3600)


def norm_url(u: str) -> str:
    return (u or "").strip()[:2000]


def norm_domain(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")[:253]


def norm_ip(ip: str) -> str:
    return (ip or "").strip()[:64]
