"""Pruebas dirigidas — REVISION-GUARDIA-FLOW #17 (residual en 7c77b37).

Entradas malformadas (puerto fuera de rango, puerto no numerico, IPv6
abierta, dominio con caracteres Unicode invalidos) deben devolver un
finding o ValueError controlado, NUNCA propagar la excepcion y dar 500.
"""
from __future__ import annotations

import pytest

from app.core.url_safety import (
    normalize_public_http_url,
    validate_public_network_target,
)


class TestNormalizePublicHttpUrlResiliente:
    def test_puerto_fuera_de_rango_no_lanza(self):
        url, finding = normalize_public_http_url("https://example.com:99999/path")
        assert url is None
        assert finding is not None
        assert "description" in finding

    def test_puerto_no_numerico_no_lanza(self):
        url, finding = normalize_public_http_url("https://example.com:abc")
        assert url is None
        assert finding is not None

    def test_ipv6_mal_formada_no_lanza(self):
        url, finding = normalize_public_http_url("https://[::1")
        assert url is None
        assert finding is not None
        assert finding["type"] == "url invalida"

    def test_hostname_unicode_invalido_no_lanza(self):
        # chr(0xD800) es un surrogate: getaddrinfo lanza UnicodeError/OSError
        host = "exa" + chr(0xD800) + "mple.com"
        url, finding = normalize_public_http_url(f"https://{host}")
        assert url is None
        assert finding is not None

    def test_dominio_inexistente_sigue_dando_finding_dns(self):
        url, finding = normalize_public_http_url("https://no-existe-wabiot-test-xyz.invalid")
        assert url is None
        assert finding is not None
        assert finding["type"] == "dns no resuelto"

    def test_url_valida_no_regresa(self):
        # ejemplo.com resuelve o no segun red; lo importante: no lanza
        url, finding = normalize_public_http_url("https://example.com")
        if url is not None:
            assert finding is None
        else:
            assert finding is not None


class TestValidatePublicNetworkTargetResiliente:
    def test_ipv6_mal_formada_en_url_lanza_valueerror_controlado(self):
        with pytest.raises(ValueError):
            validate_public_network_target("https://[::1")

    def test_objetivo_unicode_invalido_lanza_valueerror_controlado(self):
        host = "exa" + chr(0xD800) + "mple.com"
        with pytest.raises(ValueError):
            validate_public_network_target(host)
