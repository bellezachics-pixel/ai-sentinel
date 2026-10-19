"""
Regresion de seguridad 2026-10-19 — hallazgos externos verificados y corregidos.

Cubre:
- Motor de riesgo: senales extremas ya no se diluyen (pesos normalizados
  sobre los modulos realmente ejecutados; None = "no analizado").
- safe_http_get: redireccion hacia destino interno bloqueada salto a salto.
- Rate limiter: identidad de cliente sin confiar en X-Forwarded-For.
- Admin: correo en ADMIN_EMAILS ya no otorga privilegios.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.auth import UserInDB, is_admin_user
from app.core.url_safety import safe_http_get
from app.services.risk_engine import RiskEngine


# ---------------------------------------------------------------
# Motor de riesgo (P1): normalizacion de pesos
# ---------------------------------------------------------------

def test_senal_extrema_unica_no_se_diluye():
    engine = RiskEngine()
    # Contenido 100/100 siendo el UNICO modulo ejecutado -> 100 critico,
    # no 25 medio como antes de la correccion.
    result = engine.calculate_risk(content_score=100)
    assert result.total == 100
    assert result.level.value == "critical"


def test_pesos_normalizados_entre_ejecutados():
    engine = RiskEngine()
    # URL 100 + contenido 0 (ambos ejecutados): el peso se reparte entre
    # los dos, asi que queda en el peso relativo configurado.
    result = engine.calculate_risk(url_score=100, content_score=0)
    w_url = engine.weight_url
    w_content = engine.weight_content
    esperado = 100 * w_url / (w_url + w_content)
    assert abs(result.total - esperado) < 0.6


def test_modulo_no_ejecutado_excluido_del_breakdown():
    engine = RiskEngine()
    result = engine.calculate_risk(network_score=80)
    assert result.total == 80
    assert result.breakdown["network"]["analyzed"] is True
    assert result.breakdown["url"]["analyzed"] is False
    assert result.breakdown["content"]["analyzed"] is False


def test_todos_ausentes_da_cero():
    engine = RiskEngine()
    result = engine.calculate_risk()
    assert result.total == 0
    assert result.level.value == "low"


# ---------------------------------------------------------------
# safe_http_get (P1): redirecciones validadas salto a salto
# ---------------------------------------------------------------

class _RespuestaRedirect:
    status_code = 302

    def __init__(self, location: str):
        self.headers = {"location": location}


class _RespuestaOk:
    status_code = 200
    headers: dict = {}
    text = "<html>ok</html>"


def _dns_publico(host, *args, **kwargs):
    """Simula DNS: los literales IP se devuelven igual; los dominios
    resuelven a una IP publica de ejemplo."""
    import ipaddress

    try:
        ipaddress.ip_address(host)
        resolved = host
    except ValueError:
        resolved = "93.184.216.34"
    return [(2, 1, 6, "", (resolved, 443))]


def test_safe_http_get_permite_redireccion_publica():
    async def _run():
        with patch("httpx.AsyncClient.get", new=AsyncMock()) as m, patch(
            "app.core.url_safety.socket.getaddrinfo", side_effect=_dns_publico
        ):
            m.side_effect = [
                _RespuestaRedirect("https://destino-ejemplo.com/pagina"),
                _RespuestaOk(),
            ]
            return await safe_http_get("https://inicio-ejemplo.com")

    import asyncio

    resp = asyncio.run(_run())
    assert resp.status_code == 200


def test_safe_http_get_bloquea_redireccion_a_interna():
    async def _run():
        with patch("httpx.AsyncClient.get", new=AsyncMock()) as m, patch(
            "app.core.url_safety.socket.getaddrinfo", side_effect=_dns_publico
        ):
            m.side_effect = [
                _RespuestaRedirect("http://169.254.169.254/latest/meta-data/"),
            ]
            return await safe_http_get("https://atacante-ejemplo.com")

    import asyncio

    with pytest.raises(ValueError, match="bloqueada"):
        asyncio.run(_run())


def test_safe_http_get_bloquea_redireccion_a_localhost():
    async def _run():
        with patch("httpx.AsyncClient.get", new=AsyncMock()) as m, patch(
            "app.core.url_safety.socket.getaddrinfo", side_effect=_dns_publico
        ):
            m.side_effect = [_RespuestaRedirect("http://localhost:8080/admin")]
            return await safe_http_get("https://atacante-ejemplo.com")

    import asyncio

    with pytest.raises(ValueError, match="bloqueada"):
        asyncio.run(_run())


# ---------------------------------------------------------------
# Admin (P1): solo flag interno, nunca correo sin verificar
# ---------------------------------------------------------------

def _user(email: str, is_admin: bool = False) -> UserInDB:
    return UserInDB(
        id="u1",
        username="usuario",
        email=email,
        hashed_password="x",
        is_admin=is_admin,
    )


def test_admin_requiere_flag_interno():
    assert is_admin_user(_user("jefa@guardiaflow.com", is_admin=True)) is True
    assert is_admin_user(_user("jefa@guardiaflow.com")) is False


def test_correo_en_admin_emails_no_otorga_rol(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "ADMIN_EMAILS", "jefa@guardiaflow.com")
    # Correo listado pero SIN flag verificado: no es admin.
    assert is_admin_user(_user("jefa@guardiaflow.com")) is False


# ---------------------------------------------------------------
# Rate limiter (P2): X-Forwarded-For no define la identidad
# -----------------------------------------------------------------------

def test_rate_limiter_ignora_x_forwarded_for():
    from app.core.security import RateLimitMiddleware

    mw = RateLimitMiddleware(app=MagicMock())
    request = MagicMock()
    request.client.host = "203.0.113.7"
    request.headers = {"X-Forwarded-For": "1.2.3.4"}
    assert mw._get_client_ip(request) == "203.0.113.7"
