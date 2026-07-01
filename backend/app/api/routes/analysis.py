from fastapi import APIRouter, UploadFile, File, HTTPException
from app.models.schemas import (
    URLAnalysisRequest,
    EmailAnalysisRequest,
    NetworkScanRequest,
    ThreatIntelRequest,
)
from app.services.orchestrator import orchestrator

router = APIRouter(prefix="/api/v1", tags=["Analysis"])


@router.post("/analyze/url")
async def analyze_url(request: URLAnalysisRequest):
    """Analizar una URL para detectar phishing, malware y amenazas."""
    try:
        result = await orchestrator.analyze_url(request.url, request.deep_scan)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/email")
async def analyze_email(request: EmailAnalysisRequest):
    """Analizar un email para detectar phishing y spear phishing."""
    try:
        result = await orchestrator.analyze_email(
            subject=request.subject,
            sender=request.sender,
            body=request.body,
            headers=request.headers,
        )
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/qr")
async def analyze_qr(file: UploadFile = File(...)):
    """Analizar un codigo QR para detectar QRishing."""
    try:
        image_data = await file.read()
        result = await orchestrator.analyze_qr(image_data)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/media")
async def analyze_media(file: UploadFile = File(...)):
    """Analizar archivos multimedia para detectar deepfakes."""
    try:
        file_data = await file.read()
        media_type = file.content_type or "unknown"
        result = await orchestrator.analyze_media(file_data, media_type)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/network")
async def analyze_network(request: NetworkScanRequest):
    """Verificar integridad de la conexion de red."""
    try:
        result = await orchestrator.check_network(request.target_ip)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threat-intel/lookup")
async def threat_intel_lookup(request: ThreatIntelRequest):
    """Consultar fuentes de Threat Intelligence."""
    try:
        results = await orchestrator.threat_intel.query_all(
            request.indicator, request.indicator_type
        )
        return {"indicator": request.indicator, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/stats")
async def get_dashboard_stats():
    """Obtener estadisticas del dashboard."""
    try:
        stats = await orchestrator.get_dashboard_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "AI-Sentinel",
        "version": "1.0.0",
    }
