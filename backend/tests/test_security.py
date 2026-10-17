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
