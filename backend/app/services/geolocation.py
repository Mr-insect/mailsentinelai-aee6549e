"""Geolocation entry point (backward compatible): delegates to provider abstraction."""
from __future__ import annotations

from .geo_providers import geolocate  # noqa: F401  (re-export)

__all__ = ["geolocate"]
