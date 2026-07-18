import hashlib
from typing import Any
import httpx
from app.core.config import settings

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "AI-Sentinel-App"


class HIBPClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = (api_key or settings.HIBP_API_KEY or "").strip()
        self.numverify_key = (settings.NUMVERIFY_API_KEY or "").strip()
        self.twilio_sid = (settings.TWILIO_ACCOUNT_SID or "").strip()
        self.twilio_token = (settings.TWILIO_AUTH_TOKEN or "").strip()

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
        """Check phone reputation/metadata with Numverify or Twilio Lookup."""
        normalized = "".join(ch for ch in phone.strip() if ch.isdigit() or ch == "+")
        if not normalized:
            return {
                "error": "Numero de telefono invalido",
                "found": False,
                "breaches": [],
                "provider": "phone",
            }

        if self.numverify_key:
            return await self._check_phone_numverify(normalized)

        if self.twilio_sid and self.twilio_token:
            return await self._check_phone_twilio(normalized)

        return {
            "error": "Configura NUMVERIFY_API_KEY o TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN para verificar telefonos reales",
            "found": False,
            "breaches": [],
            "provider": "phone",
        }

    async def _check_phone_numverify(self, phone: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.get(
                    "https://apilayer.net/api/validate",
                    params={
                        "access_key": self.numverify_key,
                        "number": phone,
                        "format": 1,
                    },
                )
                response.raise_for_status()
                data = response.json()

                if data.get("success") is False:
                    info = data.get("error", {}).get("info", "Numverify rechazo la consulta")
                    return {
                        "error": info,
                        "found": False,
                        "breaches": [],
                        "provider": "numverify",
                    }

                valid = bool(data.get("valid"))
                line_type = data.get("line_type") or "desconocido"
                carrier = data.get("carrier") or "N/A"
                country = data.get("country_name") or data.get("country_code") or "N/A"

                return {
                    "found": not valid,
                    "breaches": [],
                    "provider": "numverify",
                    "valid": valid,
                    "phone": data.get("international_format") or phone,
                    "country": country,
                    "carrier": carrier,
                    "line_type": line_type,
                    "message": (
                        f"Numero valido: {country}, operador {carrier}, tipo {line_type}."
                        if valid
                        else "El numero no parece valido segun Numverify."
                    ),
                    "details": data,
                }
            except httpx.HTTPStatusError as exc:
                return {
                    "error": f"Error Numverify: {exc.response.status_code}",
                    "found": False,
                    "breaches": [],
                    "provider": "numverify",
                }
            except Exception as exc:
                return {
                    "error": f"Error de conexion con Numverify: {str(exc)}",
                    "found": False,
                    "breaches": [],
                    "provider": "numverify",
                }

    async def _check_phone_twilio(self, phone: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.get(
                    f"https://lookups.twilio.com/v1/PhoneNumbers/{phone}",
                    params=[("Type", "carrier"), ("Type", "caller-name")],
                    auth=(self.twilio_sid, self.twilio_token),
                )

                if response.status_code == 404:
                    return {
                        "found": True,
                        "breaches": [],
                        "provider": "twilio",
                        "valid": False,
                        "message": "Twilio no encontro este numero.",
                    }
                if response.status_code in (401, 403):
                    return {
                        "error": "Twilio Lookup no autorizado. Revisa credenciales.",
                        "found": False,
                        "breaches": [],
                        "provider": "twilio",
                    }

                response.raise_for_status()
                data = response.json()
                carrier = data.get("carrier") or {}
                caller_name = data.get("caller_name") or {}

                return {
                    "found": False,
                    "breaches": [],
                    "provider": "twilio",
                    "valid": True,
                    "phone": data.get("phone_number") or phone,
                    "country": data.get("country_code") or "N/A",
                    "carrier": carrier.get("name") or "N/A",
                    "line_type": carrier.get("type") or "desconocido",
                    "caller_name": caller_name.get("caller_name") or "N/A",
                    "message": "Numero verificado con Twilio Lookup.",
                    "details": data,
                }
            except httpx.HTTPStatusError as exc:
                return {
                    "error": f"Error Twilio Lookup: {exc.response.status_code}",
                    "found": False,
                    "breaches": [],
                    "provider": "twilio",
                }
            except Exception as exc:
                return {
                    "error": f"Error de conexion con Twilio: {str(exc)}",
                    "found": False,
                    "breaches": [],
                    "provider": "twilio",
                }


hibp_client = HIBPClient()
