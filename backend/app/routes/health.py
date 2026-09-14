from fastapi import APIRouter, Request

from ..config import get_settings
from ..services.provider_health import provider_health_snapshot

router = APIRouter(tags=["health"])


@router.get("/api/health")
async def health(request: Request) -> dict:
    return {
        "status": "ok",
        "service": "mailsentinel-ai",
        "request_id": request.headers.get("x-request-id", ""),
    }


@router.get("/api/health/providers")
async def providers() -> dict:
    """Sanitized provider status. No keys, no secrets, ever."""
    settings = get_settings()
    return {"providers": provider_health_snapshot(settings, {})}
