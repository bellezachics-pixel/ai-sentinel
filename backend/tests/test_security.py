"""Tests de seguridad: rate limiting, uploads, anti-inyeccion."""
import os

from conftest import API_PREFIX


def test_rate_limit_returns_429_after_burst(client, monkeypatch):
    # Reducir el burst necesario: default es 60/min, lo bajamos a 3.
    from app.core import security

    monkeypatch.setitem(security.RATE_LIMITS, "default", 3)

    last = None
    for _ in range(5):
        last = client.get(f"{API_PREFIX}/health")
    assert last.status_code == 429
    assert last.headers.get("X-RateLimit-Remaining") == "0"


def test_oversized_upload_rejected(auth_client):
    client, user = auth_client
    # Limite QR = 5 MB; enviamos ~6 MB.
    big = os.urandom(6 * 1024 * 1024)
    resp = client.post(
        f"{API_PREFIX}/analyze/qr",
        files={"file": ("big.png", big, "image/png")},
        headers=user["headers"],
    )
    assert resp.status_code == 413


def test_injection_pattern_in_query_rejected(client):
    # El RequestValidationMiddleware bloquea <script> en query params.
    resp = client.get(
        f"{API_PREFIX}/health",
        params={"q": "<script>alert(1)</script>"},
    )
    assert resp.status_code == 400


def test_rate_limit_por_grupo_no_comparte_presupuesto(client, auth_client):
    """Navegar el dashboard no agota el presupuesto de /auth/login (bug real)."""
    from app.core.security import rate_limit_store

    rate_limit_store.requests.clear()
    # 20 GETs a un endpoint de grupo 'default' (p.ej. dashboard)
    for _ in range(20):
        resp = client.get("/api/v1/dashboard/stats")
        assert resp.status_code in (200, 401, 402)
    # El login conserva su presupuesto propio (5/min)
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "nadie", "password": "Fake@1234"},
    )
    assert resp.status_code == 401  # no 429: el rate limit del login no se consumió
