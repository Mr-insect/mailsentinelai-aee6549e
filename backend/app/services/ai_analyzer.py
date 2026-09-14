"""REAL AI analyzer (OpenAI, analyst assistant). Sanitized evidence only."""
from __future__ import annotations

import json
import logging

import httpx

from ..models.analysis import AiVerdict

log = logging.getLogger("mailsentinel.ai")

SYSTEM = ("You are MailSentinel, a senior email security analyst ASSISTANT. "
          "You are NOT the source of truth: provider verdicts and headers are. "
          "Given sanitized email evidence and threat-intel summaries, return STRICT JSON only: "
          '{"threat_type": str, "risk_score": 0-100 int, '
          '"severity": one of SAFE|LOW|MEDIUM|HIGH|CRITICAL, "confidence": 0-100 int, '
          '"summary": str, "reasons": [str], "recommended_actions": [str], '
          '"classification": str, "executive_summary": str, '
          '"confirmed_findings": [str], "suspected_findings": [str], '
          '"unknowns": [str], "attack_techniques": [str], "reasoning_summary": str}. '
          "Rules: distinguish CONFIRMED (observed provider/header evidence) vs "
          "INFERRED (your hypothesis) vs UNKNOWN (missing evidence). "
          "Never invent IOCs, hashes, timestamps, or provider results. "
          "If evidence is weak, lower confidence and severity.")


def _fallback(reason: str) -> AiVerdict:
    return AiVerdict(threat_type="Suspicious Email", risk_score=50,
                     severity="MEDIUM", confidence=40,
                     summary=f"AI unavailable ({reason}); deterministic checks used.",
                     reasons=["AI provider unreachable; using heuristic evidence only."],
                     recommended_actions=["Quarantine Email", "Search for Similar Emails"],
                     classification="UNKNOWN (AI unavailable)",
                     executive_summary="AI analyst unavailable; verdict from deterministic evidence only.",
                     confirmed_findings=[], suspected_findings=[],
                     unknowns=["AI assessment unavailable — treat all inference as UNKNOWN."],
                     attack_techniques=[], reasoning_summary="No AI reasoning; heuristic fusion only.")


async def ai_verdict(evidence: dict, api_key: str, model: str, timeout: float) -> tuple[AiVerdict, bool]:
    """Returns (verdict, ai_used). Never raises; never logs keys or email bodies."""
    if not api_key:
        return _fallback("no key configured"), False
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            # Server-side Authorization header only; never sent to the browser.
            r = await c.post("https://api.openai.com/v1/chat/completions",
                             headers={"Authorization": "Bearer " + api_key},
                             json={"model": model, "temperature": 0.1, "response_format": {"type": "json_object"},
                                   "messages": [{"role": "system", "content": SYSTEM},
                                                {"role": "user", "content": json.dumps(evidence)[:12000]}]})
        # Authorization header stays server-side; status only is logged.
        if r.status_code != 200:
            log.warning("openai status %s", r.status_code)
            return _fallback(f"status {r.status_code}"), False
        content = r.json()["choices"][0]["message"]["content"]
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError("AI returned non-object JSON")
        sev = str(data.get("severity", "MEDIUM")).upper()
        if sev not in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            sev = "MEDIUM"
        def _str_list(v, n=8, width=300):
            return [str(x)[:width] for x in (v if isinstance(v, list) else [])][:n]
        return AiVerdict(threat_type=str(data.get("threat_type", "Suspicious Email"))[:120],
                         risk_score=max(0, min(100, int(data.get("risk_score", 50)))),
                         severity=sev,  # type: ignore
                         confidence=max(0, min(100, int(data.get("confidence", 60)))),
                         summary=str(data.get("summary", ""))[:1000],
                         reasons=_str_list(data.get("reasons"), 8, 300),
                         recommended_actions=_str_list(data.get("recommended_actions"), 10, 200),
                         classification=str(data.get("classification", data.get("threat_type", "")))[:120],
                         executive_summary=str(data.get("executive_summary", data.get("summary", "")))[:1000],
                         confirmed_findings=_str_list(data.get("confirmed_findings"), 8, 300),
                         suspected_findings=_str_list(data.get("suspected_findings"), 8, 300),
                         unknowns=_str_list(data.get("unknowns"), 8, 300),
                         attack_techniques=_str_list(data.get("attack_techniques"), 8, 120),
                         reasoning_summary=str(data.get("reasoning_summary", ""))[:800]), True
    except Exception as exc:
        log.warning("openai call failed: %s", type(exc).__name__)
        return _fallback(type(exc).__name__), False
