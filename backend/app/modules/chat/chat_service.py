"""
Servicio de chat con OpenAI para Sentinel IA.
"""
from __future__ import annotations

from openai import AsyncOpenAI
from app.core.config import settings

SYSTEM_PROMPT = """Eres Sentinel IA, un asistente experto en ciberseguridad. Tu proposito es ayudar a usuarios comunes a entender y protegerse de amenazas digitales.

Reglas:
- Responde en español (a menos que te pregunten en otro idioma).
- Explica los riesgos en lenguaje sencillo, sin tecnicismos innecesarios.
- Da recomendaciones practicas y paso a paso cuando sea posible.
- No des consejos ilegales ni eticamente cuestionables.
- Si el usuario describe una situacion sospechosa, evalua el riesgo y sugiere acciones concretas.
- Manten las respuestas concisas pero utiles.
- Si no sabes algo, admitelo en lugar de inventar.
"""

client: AsyncOpenAI | None = None


def get_client() -> AsyncOpenAI:
    global client
    if client is None:
        if not settings.OPENAI_API_KEY:
            raise RuntimeError("OPENAI_API_KEY no configurada")
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY.strip())
    return client


async def chat_with_sentinel(messages: list[dict[str, str]]) -> str:
    """
    messages: lista de dicts con 'role' y 'content'.
    Retorna la respuesta de OpenAI o un mensaje de fallback.
    """
    if not settings.OPENAI_API_KEY:
        return "Lo siento, el chat inteligente no esta configurado. Contacta al administrador."

    try:
        openai_client = get_client()
        completion = await openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                *messages,
            ],
            temperature=0.7,
            max_tokens=800,
        )
        return completion.choices[0].message.content or "No tengo una respuesta en este momento."
    except Exception as exc:
        return f"Error al consultar la IA: {str(exc)}. Intenta de nuevo en un momento."
