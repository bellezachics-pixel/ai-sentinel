import hashlib
from typing import Any
import httpx
from app.core.config import settings

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "AI-Sentinel-App"


class HIBPClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or settings.HIBP_API_KEY

    async def check_email(self, email: str) -> dict[str, Any]:
        """Check email breaches via HIBP."""
        if not self.api_key:
            return {"error": "HIBP_API_KEY no configurada", "breaches": [], "found": False}

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.get(
                    f"{HIBP_BASE_URL}/breachedaccount/{email}",
                    headers={
                        "hibp-api-key": self.api_key,
                        "user-agent": USER_AGENT,
                    },
                    params={"truncateResponse": "false"},
                )

                if response.status_code == 404:
                    return {"found": False, "breaches": [], "message": "No se encontraron filtraciones"}
                if response.status_code == 401:
                    return {"error": "API key inválida", "breaches": [], "found": False}
                if response.status_code == 429:
                    return {"error": "Rate limit alcanzado. Intenta más tarde.", "breaches": [], "found": False}

                response.raise_for_status()
                data = response.json()
                breaches = [
                    {
                        "name": b.get("Name", "Desconocido"),
                        "date": b.get("BreachDate", "N/A"),
                        "data": b.get("DataClasses", []),
                    }
                    for b in (data if isinstance(data, list) else [])
                ]
                return {"found": True, "breaches": breaches, "message": f"Se encontraron {len(breaches)} filtracion(es)"}

            except httpx.HTTPStatusError as exc:
                return {"error": f"Error HIBP: {exc.response.status_code}", "breaches": [], "found": False}
            except Exception as exc:
                return {"error": f"Error de conexión: {str(exc)}", "breaches": [], "found": False}

    async def check_password(self, password: str) -> dict[str, Any]:
        """Check password against Pwned Passwords API (k-anonymity)."""
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    headers={"user-agent": USER_AGENT},
                    params={"AddPadding": "true"},
                )
                response.raise_for_status()

                for line in response.text.splitlines():
                    hash_suffix, count = line.split(":")
                    if hash_suffix == suffix:
                        return {
                            "found": True,
                            "count": int(count),
                            "message": f"Esta contraseña apareció {int(count):,} veces en filtraciones",
                        }
                return {"found": False, "count": 0, "message": "No se encontró la contraseña en filtraciones conocidas"}

            except Exception as exc:
                return {"error": f"Error de conexión: {str(exc)}", "found": False, "count": 0}

    async def check_username(self, username: str) -> dict[str, Any]:
        """Username check - HIBP doesn't support username directly, return demo fallback."""
        return {"found": False, "breaches": [], "message": "Búsqueda por usuario no disponible en HIBP. Usa correo o contraseña."}

    async def check_phone(self, phone: str) -> dict[str, Any]:
        """Phone check - HIBP doesn't support phone directly, return demo fallback."""
        return {"found": False, "breaches": [], "message": "Búsqueda por teléfono no disponible en HIBP. Usa correo o contraseña."}


hibp_client = HIBPClient()
