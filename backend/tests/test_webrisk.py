"""
Pruebas del proveedor Google Web Risk (app.modules.threat_intel.provider).

Se monkeypatcha httpx.AsyncClient con un cliente falso: ninguna prueba
toca la red ni requiere claves reales.

Ejecutar desde backend/:
    .venv/bin/python -m pytest tests/test_webrisk.py -q
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.modules.threat_intel import provider as ti_provider
from app.modules.threat_intel.provider import ThreatIntelProvider


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class _FakeAsyncClient:
    """Imita httpx.AsyncClient para GET unico (uris:search)."""

    next_response: _FakeResponse | Exception | None = None
    last_url: str | None = None
    last_params: list[tuple[str, str]] | None = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url: str, params=None, **kwargs):
        type(self).last_url = url
        type(self).last_params = list(params or [])
        resp = type(self).next_response
        if isinstance(resp, Exception):
            raise resp
        return resp


@pytest.fixture(autouse=True)
def _fake_http(monkeypatch):
    _FakeAsyncClient.next_response = None
    _FakeAsyncClient.last_url = None
    _FakeAsyncClient.last_params = None
    monkeypatch.setattr(ti_provider.httpx, "AsyncClient", _FakeAsyncClient)
    yield


def _provider(key: str | None = "webrisk-key-test") -> ThreatIntelProvider:
    return ThreatIntelProvider(
        virustotal_key=None,
        urlscan_key=None,
        abuseipdb_key=None,
        webrisk_key=key,
    )


# ---- Comportamiento basico ----


def test_webrisk_sin_clave_reporta_no_configurado():
    asyncio.run(_test_webrisk_sin_clave_reporta_no_configurado_async())


async def _test_webrisk_sin_clave_reporta_no_configurado_async():
    result = await _provider(key=None).query_webrisk("https://example.com")
    assert result["provider"] == "google_webrisk"
    assert result["available"] is False
    assert "not configured" in (result["error"] or "")


def test_webrisk_url_limpia_da_score_cero():
    asyncio.run(_test_webrisk_url_limpia_da_score_cero_async())


async def _test_webrisk_url_limpia_da_score_cero_async():
    _FakeAsyncClient.next_response = _FakeResponse(200, {})
    result = await _provider().query_webrisk("https://wikipedia.org")
    assert result["available"] is True
    assert result["data"]["found"] is False
    assert result["data"]["is_malicious"] is False
    assert result["data"]["score"] == 0


def test_webrisk_phishing_es_malicioso():
    asyncio.run(_test_webrisk_phishing_es_malicioso_async())


async def _test_webrisk_phishing_es_malicioso_async():
    _FakeAsyncClient.next_response = _FakeResponse(
        200,
        {
            "threat": {
                "threatTypes": ["SOCIAL_ENGINEERING"],
                "expireTime": "2026-10-22T00:00:00Z",
            }
        },
    )
    result = await _provider().query_webrisk("http://fake-banco.example")
    assert result["available"] is True
    assert result["data"]["found"] is True
    assert result["data"]["is_malicious"] is True
    assert result["data"]["score"] == 90
    assert "SOCIAL_ENGINEERING" in result["data"]["threat_types"]


def test_webrisk_toma_el_tipo_mas_grave():
    asyncio.run(_test_webrisk_toma_el_tipo_mas_grave_async())


async def _test_webrisk_toma_el_tipo_mas_grave_async():
    _FakeAsyncClient.next_response = _FakeResponse(
        200,
        {"threat": {"threatTypes": ["UNWANTED_SOFTWARE", "MALWARE"]}},
    )
    result = await _provider().query_webrisk("http://mal.example")
    assert result["data"]["is_malicious"] is True
    assert result["data"]["score"] == 100


def test_webrisk_respuesta_vacia_es_limpia():
    asyncio.run(_test_webrisk_respuesta_vacia_es_limpia_async())


async def _test_webrisk_respuesta_vacia_es_limpia_async():
    _FakeAsyncClient.next_response = _FakeResponse(
        200, {"threat": {"expireTime": "2026-10-22T00:00:00Z"}}
    )
    result = await _provider().query_webrisk("https://ok.example")
    assert result["available"] is True
    assert result["data"]["found"] is False
    assert result["data"]["is_malicious"] is False


# ---- Errores de API ----


def test_webrisk_403_reporta_acceso_denegado():
    asyncio.run(_test_webrisk_403_reporta_acceso_denegado_async())


async def _test_webrisk_403_reporta_acceso_denegado_async():
    _FakeAsyncClient.next_response = _FakeResponse(403)
    result = await _provider().query_webrisk("https://example.com")
    assert result["available"] is False
    assert "denied" in (result["error"] or "")


def test_webrisk_429_reporta_cuota():
    asyncio.run(_test_webrisk_429_reporta_cuota_async())


async def _test_webrisk_429_reporta_cuota_async():
    _FakeAsyncClient.next_response = _FakeResponse(429)
    result = await _provider().query_webrisk("https://example.com")
    assert result["available"] is False
    assert "quota" in (result["error"] or "")


def test_webrisk_timeout_no_explota():
    asyncio.run(_test_webrisk_timeout_no_explota_async())


async def _test_webrisk_timeout_no_explota_async():
    _FakeAsyncClient.next_response = httpx.TimeoutException("slow")
    result = await _provider().query_webrisk("https://example.com")
    assert result["available"] is False
    assert "timed out" in (result["error"] or "")


# ---- Integracion con query_all ----


def test_query_all_url_incluye_webrisk():
    asyncio.run(_test_query_all_url_incluye_webrisk_async())


async def _test_query_all_url_incluye_webrisk_async():
    _FakeAsyncClient.next_response = _FakeResponse(200, {})
    results = await _provider().query_all("https://example.com", "url")
    providers = {r["provider"] for r in results}
    assert "google_webrisk" in providers


def test_query_all_dominio_incluye_webrisk():
    asyncio.run(_test_query_all_dominio_incluye_webrisk_async())


async def _test_query_all_dominio_incluye_webrisk_async():
    _FakeAsyncClient.next_response = _FakeResponse(200, {})
    results = await _provider().query_all("example.com", "domain")
    providers = {r["provider"] for r in results}
    assert "google_webrisk" in providers


def test_query_all_hash_no_consulta_webrisk():
    asyncio.run(_test_query_all_hash_no_consulta_webrisk_async())


async def _test_query_all_hash_no_consulta_webrisk_async():
    _FakeAsyncClient.next_response = _FakeResponse(200, {})
    results = await _provider().query_all("a" * 64, "hash")
    webrisk = [r for r in results if r["provider"] == "google_webrisk"]
    assert webrisk == []


# ---- Contrato con el orquestador (_summarize_intel) ----


def test_resultado_normalizable_por_orchestrator():
    asyncio.run(_test_resultado_normalizable_por_orchestrator_async())


async def _test_resultado_normalizable_por_orchestrator_async():
    from app.services.orchestrator import AnalysisOrchestrator

    _FakeAsyncClient.next_response = _FakeResponse(
        200,
        {"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}},
    )
    raw = await _provider().query_webrisk("http://phish.example")
    summary = AnalysisOrchestrator._summarize_intel(raw)
    assert summary["source"] == "google_webrisk"
    assert summary["is_malicious"] is True
    assert summary["score"] == 90


def test_request_usa_endpoint_y_tipos_correctos():
    asyncio.run(_test_request_usa_endpoint_y_tipos_correctos_async())


async def _test_request_usa_endpoint_y_tipos_correctos_async():
    _FakeAsyncClient.next_response = _FakeResponse(200, {})
    await _provider().query_webrisk("https://example.com")
    assert _FakeAsyncClient.last_url == "https://webrisk.googleapis.com/v1/uris:search"
    params = dict(_FakeAsyncClient.last_params or [])
    assert params.get("uri") == "https://example.com"
    assert params.get("key") == "webrisk-key-test"
    threat_params = [v for k, v in (_FakeAsyncClient.last_params or []) if k == "threatTypes"]
    assert "MALWARE" in threat_params
    assert "SOCIAL_ENGINEERING" in threat_params
