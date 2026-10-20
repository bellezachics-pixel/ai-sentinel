"""
Frente 1 — Seguridad y autenticacion: verificacion profunda (ronda 3).

Cubre a nivel HTTP con TestClient:
- Registro concurrente: dos peticiones paralelas con el mismo username
  producen exactamente una cuenta (comprobacion + insercion atomicas).
- Fuerza bruta: el bloqueo aplica SOLO a la IP de la atacante; otras IPs
  inician sesion con normalidad (limitador y ruta usan get_client_ip).
- True-Client-IP ignorada en modo directo (TRUST_PROXY_HEADERS=false):
  suplantarla no resetea ni multiplica el presupuesto del rate limiter.
- Refresh por cabecera Authorization: /auth/me acepta el access token
  renovado, y la rotacion invalida el refresh token ya usado.
- OAuth: state firmado invalido rechazado antes del intercambio con Google;
  redirect de errores siempre al frontend /app#... .
- SSRF: safe_http_get corta la descarga a 2 MB DURANTE la transferencia
  (chunks posteriores descartados) y bloquea CGNAT 100.64/10 al normalizar.
"""
import asyncio
import threading
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from conftest import AUTH_PREFIX, API_PREFIX, make_user
from app.main import app


def _limpiar_limites():
    from app.core.security import rate_limit_store

    rate_limit_store.requests.clear()
    rate_limit_store.blocked_ips.clear()
    rate_limit_store.failed_auth.clear()


# ---------------------------------------------------------------
# Registro concurrente por HTTP
# ---------------------------------------------------------------

def test_registro_concurrente_mismo_username_una_sola_cuenta(client):
    """Dos POST /register paralelos con el mismo username: 200 y 400."""
    username = f"race_{uuid.uuid4().hex[:8]}"
    resultados = []

    def _registrar():
        resp = client.post(
            f"{AUTH_PREFIX}/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": "Passw0rd!x",
            },
        )
        resultados.append(resp.status_code)

    hilos = [threading.Thread(target=_registrar) for _ in range(2)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()

    # Uno crea la cuenta; el otro es rechazado por duplicado (no 500 ni doble 200)
    assert sorted(resultados) == [200, 400], resultados

    # Identidad unica: exactamente una cuenta y el login funciona
    from app.core.auth import get_user

    assert get_user(username) is not None
    resp = client.post(
        f"{AUTH_PREFIX}/login",
        json={"username": username, "password": "Passw0rd!x"},
    )
    assert resp.status_code == 200


def test_registro_concurrente_mismo_email_rechazado(client):
    """El email duplicado tambien se detecta bajo concurrencia (no solo username)."""
    email = f"dup_{uuid.uuid4().hex[:8]}@example.com"
    resultados = []

    def _registrar(sufijo):
        resp = client.post(
            f"{AUTH_PREFIX}/register",
            json={
                "username": f"usr_{sufijo}",
                "email": email,
                "password": "Passw0rd!x",
            },
        )
        resultados.append(resp.status_code)

    hilos = [
        threading.Thread(target=_registrar, args=(uuid.uuid4().hex[:6],))
        for _ in range(2)
    ]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()

    assert sorted(resultados) == [200, 400], resultados


# ---------------------------------------------------------------
# Fuerza bruta: aislamiento por IP
# ---------------------------------------------------------------

def test_bruteforce_bloquea_solo_ip_atacante():
    """Tras 5+ fallos desde la IP atacante, otras IPs loguean sin problema.

    El contador del middleware (5/min en /auth/login) detiene la sexta
    peticion antes de que la ruta vea el umbral de fuerza bruta; para
    ejercitar el bloqueo de 15 min de la RUTA limpiamos ese contador entre
    intentos (mismo aislamiento que usa test_auth.py).
    """
    from fastapi.testclient import TestClient
    from app.core.security import rate_limit_store

    # Starlette 1.9 elimino el kwarg `client=` de TestClient; se simula la
    # IP de origen sobreescribiendo scope["client"] con un wrapper ASGI.
    def cliente_con_ip(ip: str, puerto: int):
        async def app_con_ip(scope, receive, send):
            scope["client"] = (ip, puerto)
            await app(scope, receive, send)
        return TestClient(app_con_ip)

    with cliente_con_ip("45.155.20.9", 50001) as atacante, \
            cliente_con_ip("185.220.0.9", 50002) as victima:
        _limpiar_limites()
        # Crear la cuenta de la victima desde su propia IP
        resp = victima.post(
            f"{AUTH_PREFIX}/register",
            json={
                "username": "victima_bf",
                "email": "victima_bf@example.com",
                "password": "Passw0rd!x",
            },
        )
        assert resp.status_code == 200

        # 5 intentos fallidos desde la IP atacante (limpiamos el contador
        # del middleware para que sea la RUTA quien dispare el bloqueo)
        for _ in range(5):
            rate_limit_store.requests.clear()
            resp = atacante.post(
                f"{AUTH_PREFIX}/login",
                json={"username": "victima_bf", "password": "WrongPass1!"},
            )
            assert resp.status_code == 401
        # Sexto intento: la RUTA detecta >= 5 fallos y bloquea la IP 15 min
        resp = atacante.post(
            f"{AUTH_PREFIX}/login",
            json={"username": "victima_bf", "password": "WrongPass1!"},
        )
        assert resp.status_code == 429
        assert "bloqueada" in resp.json()["detail"]

        # La victima (otra IP) NO hereda el bloqueo: login y /me OK
        resp = victima.post(
            f"{AUTH_PREFIX}/login",
            json={"username": "victima_bf", "password": "Passw0rd!x"},
        )
        assert resp.status_code == 200, resp.text
        access = resp.json()["access_token"]
        resp = victima.get(
            f"{AUTH_PREFIX}/me",
            headers={"Authorization": f"Bearer {access}"},
        )
        assert resp.status_code == 200

        # Y la IP bloqueada tampoco puede usar otros endpoints (middleware)
        resp = atacante.get(f"{API_PREFIX}/health")
        assert resp.status_code == 429


# ---------------------------------------------------------------
# True-Client-IP: suplantacion imposible en modo directo
# ---------------------------------------------------------------

def test_true_client_ip_ignorada_en_modo_directo(client, monkeypatch):
    """Con TRUST_PROXY_HEADERS=false, True-Client-IP no cambia la identidad."""
    from app.core import security

    monkeypatch.setattr(security, "TRUST_PROXY_HEADERS", False)
    monkeypatch.setitem(security.RATE_LIMITS, "default", 3)

    # Cada peticion finge una IP distinta: si la cabecera se honrara, cada
    # identidad tendria su propio presupuesto y jamas veriamos 429.
    ultima = None
    for i in range(5):
        ultima = client.get(
            f"{API_PREFIX}/health",
            headers={"True-Client-IP": f"10.9.9.{i}"},
        )
    assert ultima.status_code == 429


def test_true_client_ip_honrada_solo_en_modo_proxy(client, monkeypatch):
    """Control positivo: con TRUST_PROXY_HEADERS=true si define la identidad."""
    from app.core import security

    monkeypatch.setattr(security, "TRUST_PROXY_HEADERS", True)
    monkeypatch.setitem(security.RATE_LIMITS, "default", 3)

    ultima = None
    for i in range(5):
        ultima = client.get(
            f"{API_PREFIX}/health",
            headers={"True-Client-IP": f"10.9.9.{i}"},
        )
    assert ultima.status_code == 200  # IPs distintas: nadie agota su cupo


def test_xff_desde_ip_publica_ignorada_en_modo_directo(client, monkeypatch):
    """Modo directo: X-Forwarded-For de un cliente publico no define identidad.

    Nota: '8.8.8.8' es publica de verdad; los rangos de documentacion
    (198.51.100/24, 203.0.113/24) son is_private=True en Python 3.12+ y
    activarian la confianza de XFF para conexiones 'detras de proxy local'.
    """
    from app.core import security

    monkeypatch.setattr(security, "TRUST_PROXY_HEADERS", False)
    from app.core.security import get_client_ip

    scope_ip = "8.8.8.8"

    class _Cliente:
        host = scope_ip

    class _Request:
        client = _Cliente()
        headers = {"x-forwarded-for": "6.6.6.6, 7.7.7.7"}

    assert get_client_ip(_Request()) == scope_ip


# ---------------------------------------------------------------
# Refresh: /auth/me acepta el token renovado; rotacion anti-reuso
# ---------------------------------------------------------------

def test_refresh_por_header_y_me_acepta_token_renovado(client):
    """Refresh enviado como Bearer: el nuevo access token sirve en /auth/me."""
    user = make_user(client, username="refresh_hdr")
    resp = client.post(
        f"{AUTH_PREFIX}/refresh",
        headers={"Authorization": f"Bearer {user['refresh']}"},
    )
    assert resp.status_code == 200, resp.text
    nuevo_access = resp.json()["access_token"]

    resp = client.get(
        f"{AUTH_PREFIX}/me",
        headers={"Authorization": f"Bearer {nuevo_access}"},
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == "refresh_hdr"


def test_refresh_rotacion_rechaza_reuso_del_refresh_antiguo(client):
    """El refresh token ya canjeado queda revocado: reutilizarlo da 401."""
    user = make_user(client, username="refresh_rot")
    resp = client.post(
        f"{AUTH_PREFIX}/refresh", json={"refresh_token": user["refresh"]}
    )
    assert resp.status_code == 200

    resp = client.post(
        f"{AUTH_PREFIX}/refresh", json={"refresh_token": user["refresh"]}
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------
# OAuth: state firmado y redirect acotado al frontend /app
# ---------------------------------------------------------------

def test_oauth_state_invalida_rechazada_antes_del_intercambio(client):
    resp = client.get(
        f"{AUTH_PREFIX}/google/callback?code=falso&state=token-invalido",
        follow_redirects=False,
    )
    assert resp.status_code == 307
    location = resp.headers["location"]
    assert "/app#" in location
    assert "auth_error=google_invalid_state" in location


def test_oauth_state_valida_supera_validacion_y_va_a_exchange(client, monkeypatch):
    """State firmado correcto: NO da invalid_state; cae en el intercambio
    (Google inalcanzable en test) con redirect acotado a /app."""
    import httpx
    from app.api.routes.auth import _create_oauth_state

    class _ClienteRoto:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            raise httpx.ConnectError("sin red en tests")

    monkeypatch.setattr("app.api.routes.auth.httpx.AsyncClient", _ClienteRoto)

    state = _create_oauth_state()
    resp = client.get(
        f"{AUTH_PREFIX}/google/callback?code=xyz&state={state}",
        follow_redirects=False,
    )
    assert resp.status_code == 307
    location = resp.headers["location"]
    assert "/app#" in location
    assert "google_invalid_state" not in location
    assert "auth_error=google_exchange_failed" in location


# ---------------------------------------------------------------
# SSRF: descarga acotada durante la transferencia + CGNAT bloqueado
# ---------------------------------------------------------------

def _dns_publico(host, *args, **kwargs):
    import ipaddress

    try:
        ipaddress.ip_address(host)
        resolved = host
    except ValueError:
        resolved = "93.184.216.34"
    return [(2, 1, 6, "", (resolved, 443))]


class _RespuestaGrande:
    """Simula un servidor que intenta inflar la memoria: 5 MB en chunks."""

    status_code = 200
    headers: dict = {}

    async def aiter_bytes(self):
        yield b"a" * 1_000_000
        yield b"b" * 1_000_000  # hasta aqui 2 MB (limite): debe cortarse
        yield b"c" * 3_000_000  # esto jamas debe entrar en memoria

    async def aclose(self):
        return None


def test_safe_http_get_corta_descarga_durante_transferencia():
    """El corte a 2 MB ocurre en streaming: el chunk 'c' nunca se materializa."""
    from app.core.url_safety import safe_http_get

    async def _run():
        with patch("httpx.AsyncClient.send", new=AsyncMock()) as m, patch(
            "app.core.url_safety.socket.getaddrinfo", side_effect=_dns_publico
        ):
            m.return_value = _RespuestaGrande()
            return await safe_http_get("https://pesado-ejemplo.com")

    resp = asyncio.run(_run())
    assert len(resp.text) == 2_000_000
    assert "c" not in resp.text
    assert resp.text == "a" * 1_000_000 + "b" * 1_000_000


def test_normalize_public_url_bloquea_cgnat_100_64():
    """100.64/10 (CGNAT) no es is_private en varias versiones de Python:
    el normalizador de safe_http_get debe bloquearlo igual."""
    from app.core.url_safety import normalize_public_http_url

    with patch(
        "app.core.url_safety.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("100.64.7.7", 443))],
    ):
        url, finding = normalize_public_http_url("https://cgnat-ejemplo.com")

    assert url is None
    assert finding is not None
    assert finding["type"] == "ip privada bloqueada"
