"""
Upload hardening helpers - Guardia Flow

Validates uploaded files before any module processes them:
- Per-endpoint size limits
- Content-type and extension allowlists (cross-checked)
- Magic-byte verification (Pillow for images when available)
"""
from __future__ import annotations

import io
import os
from typing import Optional

from fastapi import HTTPException, UploadFile

# --- Per-endpoint upload size limits (bytes) ---
QR_UPLOAD_MAX_BYTES = 5 * 1024 * 1024       # 5 MB
MEDIA_UPLOAD_MAX_BYTES = 20 * 1024 * 1024   # 20 MB
FILE_UPLOAD_MAX_BYTES = 20 * 1024 * 1024    # 20 MB

_CHUNK = 1024 * 1024

# --- Extension -> magic byte signatures ---
_MAGIC_SIGNATURES: dict[str, list[bytes]] = {
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpeg": [b"\xff\xd8\xff"],
    "jpg": [b"\xff\xd8\xff"],
    "gif": [b"GIF87a", b"GIF89a"],
    "webp": [b"RIFF"],          # RIFF....WEBP verified below
    "bmp": [b"BM"],
    "wav": [b"RIFF"],           # RIFF....WAVE verified below
    "mp3": [b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"],
    "flac": [b"fLaC"],
    "ogg": [b"OggS"],
    "mp4": [b"\x00\x00\x00"],   # ....ftyp verified below
    "m4a": [b"\x00\x00\x00"],
    "pdf": [b"%PDF-"],
    "zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "rar": [b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"],
    "7z": [b"7z\xbc\xaf\x27\x1c"],
    "gz": [b"\x1f\x8b"],
}

# RIFF-based formats need the 4-byte form type at offset 8
_RIFF_FORM_TYPES: dict[str, bytes] = {
    "webp": b"WEBP",
    "wav": b"WAVE",
}


async def read_upload_limited(file: UploadFile, max_bytes: int, label: str) -> bytes:
    """Read an upload enforcing a per-endpoint size limit (streaming)."""
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(_CHUNK):
        total += len(chunk)
        if total > max_bytes:
            limit_mb = max_bytes // (1024 * 1024)
            raise HTTPException(
                status_code=413,
                detail=f"Archivo demasiado grande para {label}. Maximo {limit_mb} MB.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _sniff_format(data: bytes) -> Optional[str]:
    """Detect file format from magic bytes; None if unrecognized."""
    for ext, signatures in _MAGIC_SIGNATURES.items():
        for sig in signatures:
            if data[: len(sig)] == sig:
                if ext in _RIFF_FORM_TYPES:
                    if len(data) < 12 or data[8:12] != _RIFF_FORM_TYPES[ext]:
                        continue
                    return ext
                if ext in ("mp4", "m4a"):
                    if len(data) < 12 or data[4:8] != b"ftyp":
                        continue
                    return ext
                return ext
    return None


def _verify_with_pillow(data: bytes) -> Optional[str]:
    """Verify image bytes with Pillow; returns normalized format name or None."""
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        image = Image.open(io.BytesIO(data))
        image.verify()
        fmt = (image.format or "").lower()
        return {"jpeg": "jpg", "jfif": "jpg"}.get(fmt, fmt) or None
    except Exception:
        return None


def _looks_like_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def validate_upload(
    data: bytes,
    *,
    filename: Optional[str],
    content_type: Optional[str],
    allowed_extensions: set[str],
    allowed_content_types: set[str],
    allowed_top_levels: set[str],
    label: str,
) -> str:
    """
    Cross-check extension, declared content-type and magic bytes.

    Returns the detected/normalized extension. Raises HTTPException(400)
    on any mismatch.
    """
    declared_ext = os.path.splitext((filename or "").lower())[1].lstrip(".")
    mime = (content_type or "").split(";")[0].strip().lower()

    # (c) Extension allowlist
    if declared_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Extension de archivo no permitida para {label}: "
                f"'{declared_ext or 'desconocida'}'. "
                f"Permitidas: {sorted(allowed_extensions)}"
            ),
        )

    # (d) Magic bytes: prefer Pillow for images, fall back to signatures
    is_image = "image" in allowed_top_levels
    sniffed = _sniff_format(data)
    pillow_fmt = _verify_with_pillow(data) if is_image else None

    if pillow_fmt is not None:
        detected = pillow_fmt
    elif sniffed is not None:
        detected = sniffed
    elif declared_ext in ("txt", "csv", "json", "log") and _looks_like_text(data):
        detected = declared_ext
    else:
        raise HTTPException(
            status_code=400,
            detail=(
                f"No se pudo verificar el tipo real del archivo ({label}): "
                "las firmas de contenido no coinciden con un formato conocido."
            ),
        )

    # Cross-check: detected format must match declared extension
    equivalent = {
        "jpg": {"jpeg"},
        "jpeg": {"jpg"},
        "m4a": {"mp4"},
        "mp4": {"m4a"},
    }
    if detected != declared_ext and declared_ext not in equivalent.get(detected, set()):
        raise HTTPException(
            status_code=400,
            detail=(
                f"El contenido del archivo ({detected}) no coincide con su "
                f"extension ({declared_ext}). Posible archivo encubierto."
            ),
        )

    # (b) Content-type allowlist: declared MIME must be plausible, or we
    # accept octet-stream/missing MIME when magic bytes already validated.
    mime_ok = (
        mime in allowed_content_types
        or (mime and mime.split("/", 1)[0] in allowed_top_levels)
    )
    if not mime_ok and mime and mime != "application/octet-stream":
        raise HTTPException(
            status_code=400,
            detail=f"Tipo de contenido no permitido para {label}: '{mime}'.",
        )

    return detected
