"""
Pruebas del proveedor Google Web Risk del candidato de Codex
(app/modules/threat_intel/web_risk.py, candidato 5aa7ac4).

Delta SOLO de tests entregado por Kimi (rama test/web-risk-delta, base
codex/guardiaflow-v1-antivirus-staging). No modifica archivos del candidato.

Se monkeypatcha httpx.AsyncClient con un cliente falso: ninguna prueba
toca la red ni requiere claves reales. La clave se inyecta en
settings.GOOGLE_WEB_RISK_API_KEY en cada prueba.

Ejecutar desde backend/:
    .venv/bin/python -m pytest tests/test_web_risk_codex.py -q
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.core.config import settings
from app.modules.threat_intel import web_risk


class _FakeResponse:
    def __init__(self, status_code: int, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


class _FakeAsyncClient:
    """Imita httpx.AsyncClient para GET unico (uris:search)."""

    next_response = None
    last_url = None
    last_headers = None
    last_params = None

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, headers=None, params=None):
        type(self).last_url = url
        type(self).last_headers = dict(headers or {})
        type(self).last_params = list(params or [])
        resp = type(self).next_response
        if isinstance(resp, Exception):
            raise resp
        return resp


@pytest.fixture(autouse=True)
def _fake_http(monkeypatch):
    _FakeAsyncClient.next_response = None
    _FakeAsyncClient.last_url = None
    _FakeAsyncClient.last_headers = None
    _FakeAsyncClient.last_params = None
    monkeypatch.setattr(web_risk.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(settings, "GOOGLE_WEB_RISK_API_KEY", "webrisk-key-test")
    yield


def _run(coro):
    return asyncio.run(coro)


# ---- Sin clave ----


def test_sin_clave_devuelve_no_disponible():
    settings.GOOGLE_WEB_RISK_API_KEY = None
    result = _run(web_risk.query_web_risk("https://example.com"))
    assert result["provider"] == "google_web_risk"
    assert result["available"] is False
    # Sin clave NO se toca la red.
    assert _FakeAsyncClient.last_url is None


# ---- Respuestas API ----


def test_url_limpia_score_cero():
    _FakeAsyncClient.next_response = _FakeResponse(200, {})
    result = _run(web_risk.query_web_risk("https://wikipedia.org"))
    assert result["available"] is True
    assert result["data"]["is_malicious"] is False
    assert result["data"]["score"] == 0
    assert result["data"]["status"] == "no_match"


def test_phishing_detectado_score_100():
    _FakeAsyncClient.next_response = _FakeResponse(
        200, {"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}}
    )
    result = _run(web_risk.query_web_risk("http://fake-banco.example"))
    assert result["available"] is True
    assert result["data"]["is_malicious"] is True
    assert result["data"]["score"] == 100
    assert result["data"]["status"] == "detected"


def test_malware_detectado():
    _FakeAsyncClient.next_response = _FakeResponse(
        200, {"threat": {"threatTypes": ["MALWARE", "UNWANTED_SOFTWARE"]}}
    )
    result = _run(web_risk.query_web_risk("http://mal.example"))
    assert result["data"]["is_malicious"] is True
    assert set(result["data"]["threat_types"]) == {"MALWARE", "UNWANTED_SOFTWARE"}


def test_payload_con_claves_extra_rechazado_estricto():
    # El candidato valida estricto: respuesta con claves distintas a
    # 'threat' se trata como no disponible (posible respuesta inesperada).
    _FakeAsyncClient.next_response = _FakeResponse(
        200, {"threat": {"threatTypes": ["MALWARE"]}, "extra": 1}
    )
    result = _run(web_risk.query_web_risk("https://example.com"))
    assert result["available"] is False


def test_tipo_de_amenaza_desconocido_rechazado():
    _FakeAsyncClient.next_response = _FakeResponse(
        200, {"threat": {"threatTypes": ["POTENTIALLY_HARMFUL_APPLICATION"]}}
    )
    result = _run(web_risk.query_web_risk("https://example.com"))
    assert result["available"] is False


def test_threat_vacio_sin_tipos_no_disponible():
    _FakeAsyncClient.next_response = _FakeResponse(200, {"threat": {}})
    result = _run(web_risk.query_web_risk("https://example.com"))
    assert result["available"] is False


def test_respuesta_no_dict_no_disponible():
    _FakeAsyncClient.next_response = _FakeResponse(200, ["not", "a", "dict"])
    result = _run(web_risk.query_web_risk("https://example.com"))
    assert result["available"] is False


# ---- Errores de transporte: nunca filtran detalles ----


@pytest.mark.parametrize("status", [400, 403, 429, 500])
def test_error_http_no_disponible_sin_fuga(status):
    _FakeAsyncClient.next_response = _FakeResponse(status)
    result = _run(web_risk.query_web_risk("https://example.com"))
    assert result["available"] is False
    # El contrato del candidato: nunca exponer cadenas de error internas.
    assert result.get("error") in (None, "")


def test_timeout_no_disponible():
    _FakeAsyncClient.next_response = httpx.TimeoutException("slow")
    result = _run(web_risk.query_web_risk("https://example.com"))
    assert result["available"] is False


def test_error_conexion_no_disponible():
    _FakeAsyncClient.next_response = httpx.ConnectError("down")
    result = _run(web_risk.query_web_risk("https://example.com"))
    assert result["available"] is False


# ---- Contrato de la petición ----


def test_request_usa_header_key_y_tipos_correctos():
    _FakeAsyncClient.next_response = _FakeResponse(200, {})
    _run(web_risk.query_web_risk("https://example.com"))
    assert _FakeAsyncClient.last_url == "https://webrisk.googleapis.com/v1/uris:search"
    assert _FakeAsyncClient.last_headers.get("X-Goog-Api-Key") == "webrisk-key-test"
    params = _FakeAsyncClient.last_params or []
    assert ("uri", "https://example.com") in params
    threat_params = [v for k, v in params if k == "threatTypes"]
    assert set(threat_params) == {
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
    }
