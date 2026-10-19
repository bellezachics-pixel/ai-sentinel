from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
import asyncio
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
from app.core.billing import require_access
from app.core.integrations import get_integrations_status
from app.core.url_safety import validate_public_network_target
from app.core.upload_guard import (
    QR_UPLOAD_MAX_BYTES,
    MEDIA_UPLOAD_MAX_BYTES,
    FILE_UPLOAD_MAX_BYTES,
    read_upload_limited,
    validate_upload,
)
from app.services.orchestrator import orchestrator
from app.services.sentinel_chat import sentinel_chat

router = APIRouter(prefix="/api/v1", tags=["Analysis"])

# --- Upload allowlists ---
QR_ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "bmp", "gif"}
QR_ALLOWED_CONTENT_TYPES = {
    "image/png", "image/jpeg", "image/webp", "image/bmp", "image/gif",
}

MEDIA_ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "webp", "bmp", "gif", "tiff", "ico",
    "wav", "mp3", "flac", "ogg", "m4a", "aac",
    "mp4", "webm", "mov", "avi", "mkv",
}
MEDIA_ALLOWED_CONTENT_TYPES: set[str] = set()
MEDIA_ALLOWED_TOP_LEVELS = {"image", "audio", "video"}

FILE_ALLOWED_EXTENSIONS = {
    "pdf", "txt", "csv", "json", "log",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "7z", "tar", "gz",
}
FILE_ALLOWED_CONTENT_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/zip", "application/x-zip-compressed",
    "application/vnd.rar", "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/x-tar", "application/gzip", "application/x-gzip",
    "application/x-bzip2",
    "application/json",
}
FILE_ALLOWED_TOP_LEVELS = {"text", "application"}


def _map_media_category(content_type: str | None) -> str:
    """Map a MIME content type to the analyzer category (image/audio/auto)."""
    mime = (content_type or "").split(";")[0].strip().lower()
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("audio/"):
        return "audio"
    if mime.startswith("video/"):
        return "auto"
    raise HTTPException(
        status_code=400,
        detail=(
            f"Tipo de contenido no soportado para analisis multimedia: "
            f"'{mime or 'desconocido'}'. Se requiere image/*, audio/* o video/*."
        ),
    )


@router.post("/analyze/url")
async def analyze_url(
    request: URLAnalysisRequest,
    _access=Depends(require_access),
):
    """Analizar una URL para detectar phishing, malware y amenazas."""
    try:
        result = await orchestrator.analyze_url(request.url, request.deep_scan, user_id=_access.id if _access else None)
        return result.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/email")
async def analyze_email(
    request: EmailAnalysisRequest,
    _access=Depends(require_access),
):
    """Analizar un email para detectar phishing y spear phishing."""
    try:
        result = await orchestrator.analyze_email(
            subject=request.subject,
            sender=request.sender,
            body=request.body,
            headers=request.headers,
            user_id=_access.id if _access else None,
        )
        return result.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/message")
async def analyze_message(
    request: MessageAnalysisRequest,
    _access=Depends(require_access),
):
    """Analizar mensajes de WhatsApp, SMS o Telegram para detectar fraude."""
    try:
        result = await orchestrator.analyze_message(request.platform, request.body, user_id=_access.id if _access else None)
        return result.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/qr")
async def analyze_qr(
    file: UploadFile = File(...),
    _access=Depends(require_access),
):
    """Analizar un codigo QR para detectar QRishing."""
    try:
        image_data = await read_upload_limited(file, QR_UPLOAD_MAX_BYTES, "QR")
        validate_upload(
            image_data,
            filename=file.filename,
            content_type=file.content_type,
            allowed_extensions=QR_ALLOWED_EXTENSIONS,
            allowed_content_types=QR_ALLOWED_CONTENT_TYPES,
            allowed_top_levels={"image"},
            label="analisis QR",
        )
        result = await orchestrator.analyze_qr(image_data, user_id=_access.id if _access else None)
        return result.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/media")
async def analyze_media(
    file: UploadFile = File(...),
    _access=Depends(require_access),
):
    """Analizar archivos multimedia para detectar deepfakes."""
    try:
        file_data = await read_upload_limited(file, MEDIA_UPLOAD_MAX_BYTES, "media")
        media_type = _map_media_category(file.content_type)
        validate_upload(
            file_data,
            filename=file.filename,
            content_type=file.content_type,
            allowed_extensions=MEDIA_ALLOWED_EXTENSIONS,
            allowed_content_types=MEDIA_ALLOWED_CONTENT_TYPES,
            allowed_top_levels=MEDIA_ALLOWED_TOP_LEVELS,
            label="analisis multimedia",
        )
        result = await orchestrator.analyze_media(file_data, media_type, user_id=_access.id if _access else None)
        return result.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/file")
async def analyze_file(
    file: UploadFile = File(...),
    _access=Depends(require_access),
):
    """Analizar archivos por metadata, hash y reputacion VirusTotal."""
    try:
        file_data = await read_upload_limited(file, FILE_UPLOAD_MAX_BYTES, "archivos")
        validate_upload(
            file_data,
            filename=file.filename,
            content_type=file.content_type,
            allowed_extensions=FILE_ALLOWED_EXTENSIONS,
            allowed_content_types=FILE_ALLOWED_CONTENT_TYPES,
            allowed_top_levels=FILE_ALLOWED_TOP_LEVELS,
            label="analisis de archivos",
        )
        result = await orchestrator.analyze_file(
            file_data=file_data,
            filename=file.filename or "archivo_desconocido",
            content_type=file.content_type or "application/octet-stream",
            user_id=_access.id if _access else None,
        )
        return result.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/network")
async def analyze_network(
    request: NetworkScanRequest,
    _access=Depends(require_access),
):
    """Verificar integridad de la conexion de red."""
    # SSRF guard: reject private/loopback/link-local/reserved/metadata
    # targets with HTTP 400 before any connection is attempted.
    try:
        # getaddrinfo es bloqueante: moverlo a un hilo para no congelar
        # el event loop durante la resolucion DNS.
        validate_target = asyncio.to_thread(
            validate_public_network_target, request.target_ip or "8.8.8.8"
        )
        await validate_target
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        result = await orchestrator.check_network(request.target_ip, user_id=_access.id if _access else None)
        return result.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/identity")
async def analyze_identity(
    request: IdentityCheckRequest,
    _access=Depends(require_access),
):
    """Verificar si correo, telefono, usuario o password fue filtrado."""
    try:
        result = await orchestrator.check_identity(
            request.value, request.check_type, user_id=_access.id if _access else None
        )
        return result.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threat-intel/lookup")
async def threat_intel_lookup(
    request: ThreatIntelRequest,
    _access=Depends(require_access),
):
    """Consultar fuentes de Threat Intelligence."""
    try:
        results = await orchestrator.threat_intel.query_all(
            request.indicator, request.indicator_type
        )
        return {"indicator": request.indicator, "results": results}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    _access=Depends(require_access),
):
    """Responder preguntas de ciberseguridad con OpenAI o fallback local."""
    try:
        return await sentinel_chat.ask(request.message, request.history)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/stats")
async def get_dashboard_stats(
    _access=Depends(require_access),
):
    """Obtener estadisticas del dashboard."""
    try:
        stats = await orchestrator.get_dashboard_stats(user_id=_access.id if _access else None)
        return stats
    except HTTPException:
        raise
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
        "service": "Guardia Flow",
        "version": "1.0.0",
    }
