"""Geolocation abstraction: MaxMind (optional) + ip-api fallback.

Coordinates are ALWAYS approximate, never exact street/home location.
"""
from __future__ import annotations

import ipaddress
import logging
import os

import httpx

log = logging.getLogger("mailsentinel.geo")

_FALLBACK = {"country": "UNKNOWN", "countryCode": "--", "continent": "UNKNOWN",
             "region": "UNKNOWN", "city": "UNKNOWN", "postal_code": "",
             "lat": 0.0, "lon": 0.0, "accuracy_radius_km": None,
             "timezone": "UNKNOWN", "isp": "UNKNOWN", "asn": "UNKNOWN",
             "organization": "UNKNOWN", "connection_type": "UNKNOWN",
             "hosting": False, "proxy": False, "vpn": False, "tor": False,
             "anonymizer_type": "", "provider": "unavailable"}


def is_routable_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_reserved
                or addr.is_link_local or addr.is_multicast or addr.is_unspecified)


class GeolocationProvider:
    name = "base"


class MaxMindProvider(GeolocationProvider):
    """MaxMind GeoIP2/GeoLite2 via .mmdb files when configured."""

    name = "maxmind"

    def __init__(self):
        self._city = None
        self._asn = None
        try:
            import geoip2.database  # type: ignore
            city_db = os.environ.get("MAXMIND_CITY_DB", "")
            asn_db = os.environ.get("MAXMIND_ASN_DB", "")
            if city_db and os.path.exists(city_db):
                self._city = geoip2.database.Reader(city_db)
            if asn_db and os.path.exists(asn_db):
                self._asn = geoip2.database.Reader(asn_db)
        except Exception as exc:
            log.warning("maxmind unavailable: %s", type(exc).__name__)

    @property
    def available(self) -> bool:
        return self._city is not None

    def lookup(self, ip: str) -> dict | None:
        if not self._city:
            return None
        try:
            r = self._city.city(ip)
            asn_num, asn_org = "", "UNKNOWN"
            if self._asn:
                try:
                    a = self._asn.asn(ip)
                    asn_num = f"AS{a.autonomous_system_number}"
                    asn_org = a.autonomous_system_organization or "UNKNOWN"
                except Exception:
                    pass
            acc = r.location.accuracy_radius
            sub = r.subdivisions.most_specific.name if r.subdivisions else None
            return {
                "country": r.country.name or "UNKNOWN",
                "countryCode": r.country.iso_code or "--",
                "continent": r.continent.name or "UNKNOWN",
                "region": sub or "UNKNOWN",
                "city": r.city.name or "UNKNOWN",
                "postal_code": r.postal.code or "",
                "lat": float(r.location.latitude or 0.0),
                "lon": float(r.location.longitude or 0.0),
                "accuracy_radius_km": int(acc) if acc else None,
                "timezone": r.location.time_zone or "UNKNOWN",
                "isp": asn_org, "asn": asn_num or "UNKNOWN",
                "organization": asn_org, "connection_type": "UNKNOWN",
                "hosting": False, "proxy": False, "vpn": False,
                "tor": False, "anonymizer_type": "",
                "provider": "maxmind",
            }
        except Exception as exc:
            log.warning("maxmind lookup failed: %s", type(exc).__name__)
            return None


class IpApiProvider(GeolocationProvider):
    """Existing ip-api.com fallback (no key)."""

    name = "ip-api"

    async def lookup(self, ip: str, timeout: float) -> dict:
        try:
            async with httpx.AsyncClient(timeout=timeout) as c:
                r = await c.get(
                    f"http://ip-api.com/json/{ip}"
                    "?fields=status,country,countryCode,continent,regionName,"
                    "city,zip,lat,lon,timezone,isp,org,as,proxy,hosting")
            if r.status_code != 200:
                return dict(_FALLBACK)
            d = r.json()
            if d.get("status") != "success":
                return dict(_FALLBACK)
            return {
                "country": d.get("country", "UNKNOWN"),
                "countryCode": d.get("countryCode", "--"),
                "continent": d.get("continent", "UNKNOWN"),
                "region": d.get("regionName", "UNKNOWN"),
                "city": d.get("city", "UNKNOWN"),
                "postal_code": d.get("zip", "") or "",
                "lat": float(d.get("lat", 0.0) or 0.0),
                "lon": float(d.get("lon", 0.0) or 0.0),
                "accuracy_radius_km": None,
                "timezone": d.get("timezone", "UNKNOWN"),
                "isp": d.get("isp", "UNKNOWN"),
                "asn": d.get("as", "UNKNOWN"),
                "organization": d.get("org", "UNKNOWN"),
                "connection_type": "UNKNOWN",
                "hosting": bool(d.get("hosting", False)),
                "proxy": bool(d.get("proxy", False)),
                "vpn": False, "tor": False,
                "anonymizer_type": "proxy" if d.get("proxy") else "",
                "provider": "ip-api",
            }
        except Exception as exc:
            log.warning("geolocation failed: %s", type(exc).__name__)
            return dict(_FALLBACK)


_MAXMIND = MaxMindProvider()
_IPAPI = IpApiProvider()


async def geolocate(ip: str, timeout: float) -> dict:
    """MaxMind first when configured, ip-api fallback. Private IPs -> fallback."""
    if not is_routable_public_ip(ip):
        return dict(_FALLBACK)
    if _MAXMIND.available:
        hit = _MAXMIND.lookup(ip)
        if hit:
            return hit
    return await _IPAPI.lookup(ip, timeout)


def geo_confidence(geo: dict) -> int:
    if geo.get("provider") == "maxmind" and geo.get("accuracy_radius_km"):
        return 70
    if geo.get("provider") == "ip-api" and geo.get("country") not in ("UNKNOWN", ""):
        return 55
    return 20

