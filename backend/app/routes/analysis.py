"""Analysis routes: all secrets stay server-side; responses contain no keys."""
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

from ..config import Settings, get_settings
from ..models.analysis import AnalysisResult
from ..services.enrich import enrich_ips, enrich_urls
from ..services.parse_core import EmailParseError, parse_eml
from ..services.pipeline import analyze_bytes

router = APIRouter(tags=["analysis"])


class RawEmail(BaseModel):
    raw: str


class IntelQuery(BaseModel):
    value: str


@router.post("/api/analyze-email", response_model=AnalysisResult)
async def analyze_email(file: UploadFile = File(...),
                        settings: Settings = Depends(get_settings)):
    data = await file.read()
    if not data or len(data) > settings.MAX_EML_BYTES:
        raise HTTPException(status_code=400, detail="Invalid email file.")
    try:
        return await analyze_bytes(data, settings)
    except EmailParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Analysis failed.") from exc


@router.post("/api/analyze-raw", response_model=AnalysisResult)
async def analyze_raw(body: RawEmail, settings: Settings = Depends(get_settings)):
    raw = (body.raw or "").encode("utf-8", errors="replace")
    if not raw.strip() or len(raw) > settings.MAX_EML_BYTES:
        raise HTTPException(status_code=400, detail="Email is empty or too large.")
    try:
        return await analyze_bytes(raw, settings)
    except EmailParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Analysis failed.") from exc


@router.post("/api/analyze-url")
async def analyze_url(q: IntelQuery, settings: Settings = Depends(get_settings)):
    url = (q.value or "").strip()[:2000]
    if not url:
        raise HTTPException(status_code=400, detail="URL is required.")
    parsed = {"urls": [url], "ips": []}
    intel, _, _ = await enrich_urls(parsed, settings)
    return intel[0] if intel else {"url": url, "reputation": "UNKNOWN"}


@router.post("/api/analyze-ip")
async def analyze_ip(q: IntelQuery, settings: Settings = Depends(get_settings)):
    ip = (q.value or "").strip()[:64]
    if not ip:
        raise HTTPException(status_code=400, detail="IP is required.")
    intel, geos, _ = await enrich_ips({"urls": [], "ips": [ip]}, settings)
    return {"intel": intel[0] if intel else {"ip": ip}, "geo": geos[0] if geos else None}


@router.post("/api/analyze-domain")
async def analyze_domain(q: IntelQuery, settings: Settings = Depends(get_settings)):
    domain = (q.value or "").strip().lower()[:253]
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required.")
    parsed = {"urls": [f"http://{domain}/"], "ips": [], "domains": [domain]}
    intel, _, _ = await enrich_urls(parsed, settings)
    return intel[0] if intel else {"domain": domain, "reputation": "UNKNOWN"}


@router.post("/api/analyze-headers")
async def analyze_headers(body: RawEmail, settings: Settings = Depends(get_settings)):
    raw = (body.raw or "").encode("utf-8", errors="replace")[: settings.MAX_EML_BYTES]
    try:
        out = parse_eml(raw)
    except EmailParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    p = out["parsed"]
    return {"spf": p["spfHeader"], "dkim": p["dkimHeader"], "dmarc": p["dmarcHeader"],
            "received": p["received"], "messageSha256": out["message_sha256"]}
