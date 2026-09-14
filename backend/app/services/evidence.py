"""First-class evidence model. Every finding carries provenance.

status: confirmed | suspicious | unknown | unavailable
observed_vs_inferred: observed | inferred
AI inference must never be presented as confirmed intel.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone


def make_evidence(*, category: str, title: str, severity: str = "LOW",
                  confidence: int = 50, observed_value: str = "",
                  source: str = "", provider: str = "",
                  evidence: str = "", timestamp: str | None = None,
                  status: str = "unknown",
                  observed_vs_inferred: str = "observed",
                  related_ioc: str = "") -> dict:
    return {
        "finding_id": f"F-{uuid.uuid4().hex[:8].upper()}",
        "category": category,
        "title": title,
        "severity": severity if severity in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL") else "LOW",
        "confidence": max(0, min(100, int(confidence))),
        "observed_value": str(observed_value or "")[:2000],
        "source": source or "",
        "provider": provider or "",
        "evidence": str(evidence or "")[:2000],
        "timestamp": timestamp,
        "status": status if status in ("confirmed", "suspicious", "unknown", "unavailable") else "unknown",
        "observed_vs_inferred": observed_vs_inferred if observed_vs_inferred in ("observed", "inferred") else "observed",
        "related_ioc": related_ioc or "",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }


def unavailable_evidence(category: str, title: str, provider: str, reason: str) -> dict:
    return make_evidence(category=category, title=title, severity="LOW", confidence=0,
                         source=provider, provider=provider,
                         evidence=reason, status="unavailable",
                         observed_vs_inferred="observed")
