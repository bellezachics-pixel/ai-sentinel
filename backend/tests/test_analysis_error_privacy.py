"""HTTP regressions: internal failures stay private; controlled errors survive."""
import pytest
from fastapi import HTTPException

from app.services.orchestrator import orchestrator


@pytest.mark.parametrize("path,payload,method", [
    ("/analyze/url", {"url": "https://example.com"}, "analyze_url"),
    ("/analyze/message", {"platform": "sms", "body": "Prueba sintetica"}, "analyze_message"),
    ("/dashboard/stats", None, "get_dashboard_stats"),
])
@pytest.mark.parametrize("controlled", [False, True])
def test_analysis_error_privacy(auth_client, monkeypatch, path, payload, method, controlled):
    client, user = auth_client
    internal = "synthetic-private-token /private/internal/config"

    async def failing_service(*args, **kwargs):
        if controlled:
            raise HTTPException(status_code=429, detail="Limite temporal")
        raise RuntimeError(internal)

    monkeypatch.setattr(orchestrator, method, failing_service)
    if payload is None:
        response = client.get("/api/v1" + path, headers=user["headers"])
    else:
        response = client.post("/api/v1" + path, json=payload, headers=user["headers"])
    if controlled:
        assert response.status_code == 429
        assert response.json() == {"detail": "Limite temporal"}
    else:
        assert response.status_code == 500
        assert response.json() == {"detail": "No se pudo completar la solicitud."}
        assert internal not in response.text
