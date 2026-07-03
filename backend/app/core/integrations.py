from __future__ import annotations

from app.core.config import settings


def _configured(value: str | None) -> bool:
    return bool(value and value.strip())


def get_integrations_status() -> dict[str, dict[str, bool | str]]:
    """Return integration readiness without exposing secret values."""
    has_openai = _configured(settings.OPENAI_API_KEY)
    has_twilio = _configured(settings.TWILIO_ACCOUNT_SID) and _configured(
        settings.TWILIO_AUTH_TOKEN
    )

    return {
        "openai_chat": {
            "configured": has_openai,
            "provider": "OpenAI",
            "model": settings.OPENAI_CHAT_MODEL,
        },
        "openai_vision": {
            "configured": has_openai,
            "provider": "OpenAI",
            "model": settings.OPENAI_VISION_MODEL,
        },
        "virustotal": {
            "configured": _configured(settings.VIRUSTOTAL_API_KEY),
            "provider": "VirusTotal",
        },
        "google_fact_check": {
            "configured": _configured(settings.GOOGLE_FACT_CHECK_API_KEY),
            "provider": "Google Fact Check Tools API",
        },
        "google_login": {
            "configured": _configured(settings.GOOGLE_OAUTH_CLIENT_ID)
            and _configured(settings.GOOGLE_OAUTH_CLIENT_SECRET),
            "provider": "Google OAuth",
            "client_id_configured": _configured(settings.GOOGLE_OAUTH_CLIENT_ID),
            "client_secret_configured": _configured(settings.GOOGLE_OAUTH_CLIENT_SECRET),
            "redirect_uri_configured": _configured(settings.GOOGLE_OAUTH_REDIRECT_URI),
            "frontend_url_configured": _configured(settings.FRONTEND_URL),
        },
        "numverify": {
            "configured": _configured(settings.NUMVERIFY_API_KEY),
            "provider": "Numverify",
        },
        "twilio_lookup": {
            "configured": has_twilio,
            "provider": "Twilio Lookup",
            "country": settings.TWILIO_LOOKUP_FROM_COUNTRY,
        },
        "urlscan": {
            "configured": _configured(settings.URLSCAN_API_KEY),
            "provider": "urlscan.io",
        },
        "abuseipdb": {
            "configured": _configured(settings.ABUSEIPDB_API_KEY),
            "provider": "AbuseIPDB",
        },
    }
