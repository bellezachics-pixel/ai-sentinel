from __future__ import annotations

from typing import Iterable

import httpx

from app.core.config import settings
from app.models.schemas import ChatMessage, ChatResponse


SYSTEM_PROMPT = """
Eres Sentinel IA, un asistente de ciberseguridad para usuarios no tecnicos.
Responde en espanol claro, con pasos concretos y tono calmado.
No inventes resultados de escaneos. Si falta contexto, dilo y pide el dato minimo.
Para emergencias de seguridad, prioriza contencion: desconectar, cambiar contrasenas,
activar 2FA, revisar sesiones y contactar soporte oficial.
""".strip()


LOCAL_RESPONSES: dict[str, str] = {
    "phishing": "El phishing intenta robar datos haciendose pasar por una entidad confiable. No abras enlaces sospechosos, revisa el dominio, no compartas codigos 2FA y entra al servicio escribiendo la direccion oficial.",
    "password": "Usa una contrasena unica de 12 caracteres o mas, con gestor de contrasenas y 2FA. No reutilices claves entre bancos, correo y redes sociales.",
    "vpn": "Una VPN ayuda en redes publicas, pero no reemplaza buenas practicas. Usa proveedores confiables, evita VPN gratuitas desconocidas y manten 2FA activo.",
    "wifi": "Para proteger tu WiFi: usa WPA2/WPA3, cambia la clave del router, desactiva WPS, actualiza firmware y separa una red de invitados.",
    "malware": "Si sospechas malware: desconecta internet, no ingreses contrasenas, escanea con una herramienta confiable, elimina apps raras y cambia claves desde otro dispositivo.",
}


def _local_reply(message: str) -> str:
    lower = message.lower()
    for keyword, reply in LOCAL_RESPONSES.items():
        if keyword in lower:
            return reply
    return (
        "Puedo ayudarte con esa situacion. Como primer paso, no compartas datos sensibles "
        "ni abras enlaces desconocidos. Dime que viste, donde ocurrio y si ya hiciste clic "
        "o descargaste algo para darte pasos mas precisos."
    )


def _build_messages(message: str, history: Iterable[ChatMessage]) -> list[dict[str, str]]:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for item in list(history)[-8:]:
        if item.role in {"user", "assistant"}:
            messages.append({"role": item.role, "content": item.content})
    messages.append({"role": "user", "content": message})
    return messages


class SentinelChatService:
    async def ask(self, message: str, history: list[ChatMessage]) -> ChatResponse:
        if not settings.OPENAI_API_KEY:
            return ChatResponse(
                reply=_local_reply(message),
                provider="local",
                configured=False,
            )

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": settings.OPENAI_CHAT_MODEL,
                        "messages": _build_messages(message, history),
                        "temperature": 0.2,
                        "max_tokens": 700,
                    },
                )
                response.raise_for_status()
                data = response.json()
                reply = data["choices"][0]["message"]["content"].strip()
                return ChatResponse(
                    reply=reply,
                    provider="openai",
                    model=settings.OPENAI_CHAT_MODEL,
                    configured=True,
                )
        except Exception:
            return ChatResponse(
                reply=(
                    "No pude conectar con OpenAI ahora mismo. Mientras tanto: "
                    f"{_local_reply(message)}"
                ),
                provider="local_fallback",
                model=settings.OPENAI_CHAT_MODEL,
                configured=True,
            )


sentinel_chat = SentinelChatService()
