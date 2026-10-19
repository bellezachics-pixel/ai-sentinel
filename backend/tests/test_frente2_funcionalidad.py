"""Frente 2 - Funcionalidad y estabilidad.

Recorrido funcional del orquestador SIN red externa (todo mockado):

- QR con payload ``javascript:`` genera hallazgo critical.
- Email en espanol con "URGENTE verifique su cuenta" genera hallazgos de
  urgencia y de solicitud de credenciales.
- analyze_url marca paypal-secure.net como brand_impersonation y NO marca
  a paypal.com (apex oficial).
- Todo hallazgo que llega al frontend tiene type/description/severity.
- _summarize_intel mapea AbuseIPDB (abuse_confidence_score) y VirusTotal
  (last_analysis_stats).
- Las recomendaciones especificas se disparan con los types normalizados.
"""
import asyncio
import io

import pytest

from conftest import API_PREFIX
from app.services.orchestrator import orchestrator, AnalysisOrchestrator


# --- Fakes deterministas (sin red externa) -------------------------------


class _FakeHeaderAnalyzer:
    async def analyze_headers(self, url):
        return {"score": 0, "findings": []}


class _FakeNetworkAnalyzer:
    async def check_network_integrity(self, target):
        return {
            "score": 0,
            "findings": [
                {
                    "category": "network_integrity",
                    "pattern_type": "connection_ok",
                    "severity": "low",
                    "detail": "Conexion estable sin anomalias (fake).",
                }
            ],
        }


class _FakeHIBPClient:
    async def check_email(self, value):
        return {
            "found": False,
            "breaches": [],
            "message": "No se encontraron filtraciones (fake).",
        }

    async def check_password(self, value):
        return await self.check_email(value)

    async def check_username(self, value):
        return await self.check_email(value)

    async def check_phone(self, value):
        return await self.check_email(value)


def _fake_normalize(url):
    """Simula normalize_public_http_url sin resolver DNS."""
    if not url:
        return None, {"type": "url vacia", "severity": "medium", "description": "vacia"}
    if "://" not in url:
        url = f"https://{url}"
    return url, None


async def _failing_http_get(url, timeout=10.0, **kwargs):
    raise ConnectionError("sin red en tests")


@pytest.fixture()
def no_network(monkeypatch):
    """Aislarse de DNS/HTTP: normalizacion directa y fetch de contenido roto."""
    monkeypatch.setattr(
        "app.services.orchestrator.normalize_public_http_url", _fake_normalize
    )
    monkeypatch.setattr("app.services.orchestrator.safe_http_get", _failing_http_get)
    monkeypatch.setattr(orchestrator, "_header_analyzer", _FakeHeaderAnalyzer())
    monkeypatch.setattr(orchestrator, "_network_analyzer", _FakeNetworkAnalyzer())
    monkeypatch.setattr(orchestrator, "_identity_client", _FakeHIBPClient())


def _qr_analyzer_with_payload(payload: str):
    """QRishingAnalyzer real cuyo decode devuelve un payload controlado."""
    from app.modules.qrishing.analyzer import QRishingAnalyzer

    analyzer = QRishingAnalyzer()
    analyzer._decode_qr = lambda image_data: [  # noqa: SLF001
        {"data": payload, "type": "QRCODE", "rect": None, "quality": None}
    ]
    return analyzer


def _assert_findings_normalized(findings):
    assert isinstance(findings, list)
    for f in findings:
        assert f.get("type"), f"hallazgo sin type: {f}"
        assert f.get("description"), f"hallazgo sin description: {f}"
        assert f.get("severity") in {"low", "medium", "high", "critical"}, f


# --- QR: javascript:/data: deben ser criticos -----------------------------


def test_qr_javascript_payload_es_critico(monkeypatch):
    analyzer = _qr_analyzer_with_payload("javascript:alert(document.cookie)")
    monkeypatch.setattr(orchestrator, "_qrishing_analyzer", analyzer)

    result = asyncio.run(orchestrator.analyze_qr(b"imagen-fake"))

    criticos = [f for f in result.findings if f["severity"] == "critical"]
    assert criticos, result.findings
    assert any("suspicious scheme" in f["type"] for f in criticos)
    _assert_findings_normalized(result.findings)


def test_qr_data_payload_es_critico(monkeypatch):
    analyzer = _qr_analyzer_with_payload(
        "data:text/html,<script>fetch('//evil.example/x')</script>"
    )
    monkeypatch.setattr(orchestrator, "_qrishing_analyzer", analyzer)

    result = asyncio.run(orchestrator.analyze_qr(b"imagen-fake"))

    assert any(f["severity"] == "critical" for f in result.findings), result.findings


def test_qr_https_benigno_sin_criticos(monkeypatch):
    analyzer = _qr_analyzer_with_payload("https://www.ejemplo-valido.com/pagina")
    monkeypatch.setattr(orchestrator, "_qrishing_analyzer", analyzer)

    result = asyncio.run(orchestrator.analyze_qr(b"imagen-fake"))

    assert not [f for f in result.findings if f["severity"] == "critical"]


# --- Email en espanol: urgencia y credenciales ----------------------------


EMAIL_URGENTE = (
    "Estimado cliente: URGENTE verifique su cuenta en las proximas 24 horas. "
    "Su cuenta sera suspendida si no confirma su identidad. "
    "Ingrese su contrasena para actualizar sus datos."
)


def test_email_espanol_urgencia_y_credenciales(no_network, auth_client):
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/email",
        json={
            "subject": "URGENTE: verifique su cuenta",
            "sender": "soporte@paypal.com",
            "body": EMAIL_URGENTE,
        },
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    findings = resp.json()["findings"]
    types = {f["type"] for f in findings}
    assert "urgency" in types, types
    assert "credential request" in types, types
    _assert_findings_normalized(findings)


# --- URL: suplantacion de marca vs dominio oficial ------------------------


def test_url_marca_falsa_es_suplantacion(no_network, auth_client):
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/url",
        json={"url": "http://paypal-secure.net/account/login"},
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    findings = resp.json()["findings"]
    assert any(f["type"] == "brand impersonation" for f in findings), findings
    _assert_findings_normalized(findings)


def test_url_apex_oficial_no_es_suplantacion(no_network, auth_client):
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/url",
        json={"url": "https://paypal.com"},
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    findings = resp.json()["findings"]
    assert not any("brand impersonation" in f["type"] for f in findings), findings
    assert not any("suplantacion" in f["description"].lower() for f in findings)


# --- Invariante: ningun analisis devuelve hallazgos sin normalizar --------


def test_message_findings_normalizados(no_network, auth_client):
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/message",
        json={"platform": "whatsapp", "body": EMAIL_URGENTE},
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    findings = resp.json()["findings"]
    assert findings, "un mensaje de phishing obvio debe generar hallazgos"
    _assert_findings_normalized(findings)


def test_qr_via_api_findings_normalizados(no_network, auth_client, monkeypatch):
    from PIL import Image

    # El upload_guard valida magic bytes: debe ser un PNG real.
    buf = io.BytesIO()
    Image.new("RGB", (32, 32), (200, 200, 200)).save(buf, format="PNG")

    monkeypatch.setattr(
        orchestrator,
        "_qrishing_analyzer",
        _qr_analyzer_with_payload("javascript:alert(1)"),
    )
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/qr",
        files={"file": ("qr.png", buf.getvalue(), "image/png")},
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    findings = resp.json()["findings"]
    assert any(f["severity"] == "critical" for f in findings), findings
    _assert_findings_normalized(findings)


def test_media_findings_normalizados(no_network, auth_client):
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (64, 64), (30, 30, 30)).save(buf, format="PNG")

    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/media",
        files={"file": ("foto.png", buf.getvalue(), "image/png")},
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    _assert_findings_normalized(resp.json()["findings"])


def test_network_findings_normalizados(no_network, auth_client):
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/network",
        json={"target_ip": "8.8.8.8"},
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    findings = resp.json()["findings"]
    assert findings, "el analisis de red debe explicar su estado"
    _assert_findings_normalized(findings)


def test_identity_findings_normalizados(no_network, auth_client):
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/identity",
        json={"value": "persona@example.com", "check_type": "email"},
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    findings = resp.json()["findings"]
    assert findings
    _assert_findings_normalized(findings)


def test_file_findings_normalizados(no_network, auth_client):
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/file",
        files={"file": ("datos.zip", b"PK\x03\x04fake-zip-bytes", "application/zip")},
        headers=user["headers"],
    )
    assert resp.status_code == 200, resp.text
    findings = resp.json()["findings"]
    assert findings, "un ZIP debe generar al menos el hallazgo de comprimido"
    _assert_findings_normalized(findings)


# --- summarize_intel: mapeo por proveedor ---------------------------------


def test_summarize_intel_abuseipdb():
    summary = AnalysisOrchestrator._summarize_intel(
        {
            "provider": "abuseipdb",
            "available": True,
            "data": {"abuse_confidence_score": 87, "is_malicious": True},
        }
    )
    assert summary["source"] == "abuseipdb"
    assert summary["score"] == 87
    assert summary["is_malicious"] is True


def test_summarize_intel_virustotal_deriva_score_de_stats():
    summary = AnalysisOrchestrator._summarize_intel(
        {
            "provider": "virustotal",
            "available": True,
            "data": {
                "is_malicious": True,
                "last_analysis_stats": {
                    "malicious": 6,
                    "suspicious": 1,
                    "undetected": 60,
                    "harmless": 10,
                },
            },
        }
    )
    assert summary["source"] == "virustotal"
    assert summary["score"] == 60  # 6 motores maliciosos * 10
    assert summary["is_malicious"] is True


def test_summarize_intel_sin_detecciones():
    summary = AnalysisOrchestrator._summarize_intel(
        {
            "provider": "virustotal",
            "available": True,
            "data": {"found": False},
        }
    )
    assert summary["score"] == 0
    assert summary["is_malicious"] is False


# --- Recomendaciones especificas con types normalizados --------------------


def test_recomendacion_credential_harvesting_con_type_normalizado():
    from app.services.risk_engine import risk_engine

    score = risk_engine.calculate_risk(content_score=80)
    # El type normalizado usa espacios; el category conserva el guion bajo.
    findings = [
        {
            "type": "external form action",
            "category": "credential_harvesting",
            "severity": "critical",
            "description": "Formulario POST hacia dominio externo.",
        }
    ]
    recs = orchestrator._generate_recommendations(score, findings)  # noqa: SLF001
    assert any("Formulario de recoleccion" in r for r in recs), recs


def test_recomendacion_social_engineering_con_type_normalizado():
    from app.services.risk_engine import risk_engine

    score = risk_engine.calculate_risk(content_score=70)
    findings = [
        {
            "type": "credential request",
            "category": "credential_request",
            "severity": "high",
            "description": "verifique su cuenta",
        },
        {
            "type": "urgency",
            "category": "social_engineering",
            "severity": "high",
            "description": "URGENTE",
        },
    ]
    recs = orchestrator._generate_recommendations(score, findings)  # noqa: SLF001
    assert any("ingenieria social" in r for r in recs), recs
