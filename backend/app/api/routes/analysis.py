from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from app.models.schemas import (
    ChatRequest,
    ChatResponse,
    URLAnalysisRequest,
    EmailAnalysisRequest,
    MessageAnalysisRequest,
    NetworkScanRequest,
    ThreatIntelRequest,
    IdentityCheckRequest,
)
from app.core.auth import require_analysis_access
from app.core.integrations import get_integrations_status
from app.services.orchestrator import orchestrator
from app.services.sentinel_chat import sentinel_chat

router = APIRouter(prefix="/api/v1", tags=["Analysis"])


@router.post("/analyze/url")
async def analyze_url(
    request: URLAnalysisRequest,
    _access=Depends(require_analysis_access),
):
    """Analizar una URL para detectar phishing, malware y amenazas."""
    try:
        result = await orchestrator.analyze_url(request.url, request.deep_scan)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/email")
async def analyze_email(
    request: EmailAnalysisRequest,
    _access=Depends(require_analysis_access),
):
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


@router.post("/analyze/message")
async def analyze_message(
    request: MessageAnalysisRequest,
    _access=Depends(require_analysis_access),
):
    """Analizar mensajes de WhatsApp, SMS o Telegram para detectar fraude."""
    try:
        result = await orchestrator.analyze_message(request.platform, request.body)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/qr")
async def analyze_qr(
    file: UploadFile = File(...),
    _access=Depends(require_analysis_access),
):
    """Analizar un codigo QR para detectar QRishing."""
    try:
        image_data = await file.read()
        result = await orchestrator.analyze_qr(image_data)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/media")
async def analyze_media(
    file: UploadFile = File(...),
    _access=Depends(require_analysis_access),
):
    """Analizar archivos multimedia para detectar deepfakes."""
    try:
        file_data = await file.read()
        media_type = file.content_type or "unknown"
        result = await orchestrator.analyze_media(file_data, media_type)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/file")
async def analyze_file(
    file: UploadFile = File(...),
    _access=Depends(require_analysis_access),
):
    """Analizar archivos por metadata, hash y reputacion VirusTotal."""
    try:
        file_data = await file.read()
        result = await orchestrator.analyze_file(
            file_data=file_data,
            filename=file.filename or "archivo_desconocido",
            content_type=file.content_type or "application/octet-stream",
        )
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/network")
async def analyze_network(
    request: NetworkScanRequest,
    _access=Depends(require_analysis_access),
):
    """Verificar integridad de la conexion de red."""
    try:
        result = await orchestrator.check_network(request.target_ip)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/identity")
async def analyze_identity(
    request: IdentityCheckRequest,
    _access=Depends(require_analysis_access),
):
    """Verificar si correo, telefono, usuario o password fue filtrado."""
    try:
        result = await orchestrator.check_identity(
            request.value, request.check_type
        )
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threat-intel/lookup")
async def threat_intel_lookup(
    request: ThreatIntelRequest,
    _access=Depends(require_analysis_access),
):
    """Consultar fuentes de Threat Intelligence."""
    try:
        results = await orchestrator.threat_intel.query_all(
            request.indicator, request.indicator_type
        )
        return {"indicator": request.indicator, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    _access=Depends(require_analysis_access),
):
    """Responder preguntas de ciberseguridad con OpenAI o fallback local."""
    try:
        return await sentinel_chat.ask(request.message, request.history)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/stats")
async def get_dashboard_stats(
    _access=Depends(require_analysis_access),
):
    """Obtener estadisticas del dashboard."""
    try:
        stats = await orchestrator.get_dashboard_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/integrations/status")
async def integrations_status():
    """Obtener estado de configuracion de integraciones externas."""
    return get_integrations_status()


@router.get("/health")
async def health_check():
    """Health check endpoint (publico)."""
    return {
        "status": "healthy",
        "service": "AI-Sentinel",
        "version": "1.0.0",
    }
