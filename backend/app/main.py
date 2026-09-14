"""MailSentinel AI — FastAPI backend.

Production-oriented MVP: receives raw .EML uploads, parses them
server-side as untrusted input, enriches IOCs with LIVE threat
intelligence (VirusTotal / AbuseIPDB / Google Safe Browsing),
asks a REAL AI model (OpenAI) for a structured verdict over
sanitized evidence, then returns one normalized AnalysisResult
compatible with the existing React frontend (src/lib/types.ts).

All secret keys live ONLY in server environment variables.
Nothing secret is ever returned to the browser.
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import get_settings
from .routes import analysis, health

settings = get_settings()

app = FastAPI(
    title="MailSentinel AI API",
    description="Live email threat analysis: MIME parsing, IOC extraction, "
    "threat intelligence, AI verdict, normalized AnalysisResult.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

app.include_router(health.router)
app.include_router(analysis.router)


# ---------------------------------------------------------------------------
# Security middleware (Phase 19): request IDs, sanitized structured logging,
# optional rate limiting. Email contents and AI output are UNTRUSTED — they
# are never logged, and neither are API keys.
# ---------------------------------------------------------------------------
import logging
import time
import uuid
from collections import defaultdict, deque

access_log = logging.getLogger("mailsentinel.access")

# Request-ID assignment + sanitized access log (status, method, path, ms —
# never bodies, headers, IPs of submitters, or provider payloads).
@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        access_log.exception("request_id=%s method=%s path=%s UNHANDLED_ERROR",
                             request_id, request.method, request.url.path)
        response = JSONResponse(status_code=500, content={"detail": "Internal server error.",
                                                          "request_id": request_id})
    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    response.headers["x-request-id"] = request_id
    access_log.info("request_id=%s method=%s path=%s status=%s duration_ms=%s",
                    request_id, request.method, request.url.path,
                    response.status_code, elapsed_ms)
    return response


# Simple in-memory sliding-window rate limiter for public deployments.
# Off by default (ENABLE_RATE_LIMITING=false); behind a real proxy/WAF a
# proper limiter is preferred, this is a safe default for the MVP.
_RATE_LIMIT = 60  # requests per window per client
_RATE_WINDOW_S = 60.0
_hits: dict[str, deque] = defaultdict(lambda: deque(maxlen=256))

@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if not settings.ENABLE_RATE_LIMITING:
        return await call_next(request)
    key = request.client.host if request.client else "unknown"
    now = time.monotonic()
    window = _hits[key]
    while window and now - window[0] > _RATE_WINDOW_S:
        window.popleft()
    if len(window) >= _RATE_LIMIT:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try again shortly."})
    window.append(now)
    return await call_next(request)

