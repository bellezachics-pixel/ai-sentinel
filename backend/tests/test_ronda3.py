"""
Tests de la Ronda 3 (crashes, IP real, webhooks consistentes).

Sin red, sin claves reales: todo es unitario o con mocks.
"""
from unittest.mock import MagicMock, patch

import pytest

from app.core.security import MALICIOUS_PATTERNS, get_client_ip
from app.modules.qrishing.analyzer import QRishingAnalyzer
from app.modules.url_analyzer.analyzer import URLAnalyzer
from app.services.orchestrator import AnalysisOrchestrator

qr = QRishingAnalyzer()
url_analyzer = URLAnalyzer()


# ============================================================
# Bloque A: normalizacion de hallazgos
# ============================================================

def test_collect_findings_normaliza_campos_distintos():
    collected = AnalysisOrchestrator._collect_findings([
        ("nlp_analysis", {"findings": [
            {"pattern_type": "urgency", "detail": "pide actuar ya", "severity": "high"},
        ]}),
        ("content_analysis", {"findings": [
            {"category": "phishing", "matched_text": "ganaste un premio"},
        ]}),
        ("modulo_roto", None),          # resultado no-dict: se ignora
        ("vacio", {"findings": []}),    # sin hallazgos
        ("con_basura", {"findings": ["no-es-dict", {"type": "ok"}]}),
    ])
    assert len(collected) == 3
    assert collected[0]["type"] == "urgency"
    assert collected[0]["description"] == "pide actuar ya"
    assert collected[0]["source"] == "nlp_analysis"
    assert collected[1]["type"] == "phishing"
    assert collected[1]["description"] == "ganaste un premio"
    assert collected[2]["type"] == "ok"
    assert all("severity" in f for f in collected)


def test_normalize_finding_rellena_type_y_description():
    out = AnalysisOrchestrator._normalize_finding({"severity": "medium"})
    assert out["type"] == "hallazgo"
    assert out["description"] == "hallazgo"
    assert out["severity"] == "medium"


# ============================================================
# Bloque B: IP real de la clienta (True-Client-IP)
# ============================================================

def _request(headers: dict, host: str = "8.8.8.4"):
    from starlette.requests import Request

    raw = [
        (k.lower().encode(), v.encode()) for k, v in headers.items()
    ]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "headers": raw,
        "client": (host, 12345),
        "scheme": "https",
        "server": ("test", 443),
        "query_string": b"",
    }
    return Request(scope)


@pytest.fixture()
def modo_proxy(monkeypatch):
    """Simula el despliegue detras del proxy de Render."""
    monkeypatch.setattr("app.core.security.TRUST_PROXY_HEADERS", True)


def test_true_client_ip_tiene_prioridad(modo_proxy):
    req = _request({"True-Client-IP": "198.51.100.9", "X-Forwarded-For": "1.1.1.1"})
    assert get_client_ip(req) == "198.51.100.9"


def test_xff_primera_posicion_en_modo_proxy(modo_proxy):
    # El borde anade la IP original de la visitante como PRIMER valor de XFF.
    req = _request({"X-Forwarded-For": "198.51.100.9, 10.0.0.2"})
    assert get_client_ip(req) == "198.51.100.9"


def test_true_client_ip_invalida_se_descarta(modo_proxy):
    req = _request({"True-Client-IP": "no-es-una-ip", "X-Forwarded-For": "1.1.1.1"})
    assert get_client_ip(req) == "1.1.1.1"


def test_modo_directo_ignora_cabeceras_falsificables(monkeypatch):
    # Sin proxy confiable (default): la clienta puede mandar cualquier
    # True-Client-IP/XFF y NO debe alterar su identidad.
    monkeypatch.setattr("app.core.security.TRUST_PROXY_HEADERS", False)
    req = _request({"True-Client-IP": "1.2.3.4"}, host="8.8.8.4")
    assert get_client_ip(req) == "8.8.8.4"
    req2 = _request({"X-Forwarded-For": "1.2.3.4"}, host="8.8.8.4")
    assert get_client_ip(req2) == "8.8.8.4"


def test_xff_solo_detras_de_proxy_privado(monkeypatch):
    # Proxy local privado (docker-compose): el ultimo valor de XFF es la
    # IP real, aunque el modo proxy confiable este apagado.
    monkeypatch.setattr("app.core.security.TRUST_PROXY_HEADERS", False)
    req = _request({"X-Forwarded-For": "8.8.8.8, 198.51.100.9"}, host="10.0.0.2")
    assert get_client_ip(req) == "198.51.100.9"


def test_sin_headers_usa_client_host():
    req = _request({}, host="8.8.8.4")
    assert get_client_ip(req) == "8.8.8.4"


# ============================================================
# Bloque C: regex anti-inyeccion sin falsos positivos
# ============================================================

def test_session_id_no_es_inyeccion():
    url = "https://api.guardiaflow.com/callback?session_id=abc123&next=/app"
    for pattern in MALICIOUS_PATTERNS:
        assert not pattern.search(url), f"falso positivo con {pattern.pattern}"


def test_event_handler_html_si_es_inyeccion():
    assert any(p.search('<img src=x onclick="evil()">') for p in MALICIOUS_PATTERNS)
    assert any(p.search("javascript:alert(1)") for p in MALICIOUS_PATTERNS)


# ============================================================
# Bloque D: QR con esquemas ejecutables y marcas oficiales
# ============================================================

def test_qr_javascript_es_critico():
    findings = qr._analyze_non_url_data("javascript:alert(document.cookie)")
    assert any(f.get("severity") == "critical" for f in findings)


def test_qr_data_uri_es_critico():
    findings = qr._analyze_non_url_data("data:text/html,<script>alert(1)</script>")
    assert any(f.get("severity") == "critical" for f in findings)


def test_dominio_oficial_no_es_suplantacion():
    assert QRishingAnalyzer._is_official_brand_host("paypal.com", "paypal")
    assert QRishingAnalyzer._is_official_brand_host("www.paypal.com", "paypal")
    # accounts.google.com.mx: subdominio de un TLD oficial (.com.mx no
    # esta en la lista, asi que NO se considera apex oficial protegido...
    # pero "google.com.mx" si lo seria con la lista actual? No: la lista
    # verifica "{brand}.{tld}" exacto o subdominio de el. com.mx no es un
    # tld de la lista, por tanto es False (se evalua como posible marca).
    assert not QRishingAnalyzer._is_official_brand_host("accounts.google.com.mx", "google")
    assert not QRishingAnalyzer._is_official_brand_host("paypal.com.evil.com", "paypal")
    assert not QRishingAnalyzer._is_official_brand_host("paypal-secure.net", "paypal")


def test_url_analyzer_marca_oficial_no_falso_positivo():
    findings = url_analyzer._check_phishing_patterns("https://paypal.com/signin")
    assert not any(f.get("pattern") == "brand_impersonation" for f in findings)
    findings2 = url_analyzer._check_phishing_patterns("https://paypal-secure-login.com/signin")
    assert any(f.get("pattern") == "brand_impersonation" for f in findings2)


# ============================================================
# Bloque D: mapeo de threat intel
# ============================================================

def test_summarize_intel_abuseipdb():
    out = AnalysisOrchestrator._summarize_intel({
        "provider": "abuseipdb",
        "available": True,
        "data": {"abuse_confidence_score": 85, "is_malicious": True},
        "error": None,
    })
    assert out["source"] == "abuseipdb"
    assert out["score"] == 85
    assert out["is_malicious"] is True


def test_summarize_intel_virustotal_deriva_score():
    out = AnalysisOrchestrator._summarize_intel({
        "provider": "virustotal",
        "available": True,
        "data": {
            "last_analysis_stats": {"malicious": 12, "suspicious": 3, "harmless": 60},
            "is_malicious": True,
        },
        "error": None,
    })
    assert out["score"] == min(100, 120) == 100
    assert out["is_malicious"] is True


def test_summarize_intel_limpio_cero():
    out = AnalysisOrchestrator._summarize_intel({
        "provider": "urlscan", "available": True, "data": {}, "error": None,
    })
    assert out["score"] == 0
    assert out["is_malicious"] is False


# ============================================================
# Bloque D: webhooks consistentes (sin reactivar acceso)
# ============================================================

def _billing_module():
    from app.api.routes import billing as billing_routes
    return billing_routes


def _setup_customer_record(monkeypatch, user_id="u-webhook-1", status="canceled",
                           last_event_created=None):
    from app.core import billing_store

    record = {"status": status, "stripe_customer_id": "cus_test"}
    if last_event_created is not None:
        record["last_event_created"] = last_event_created
    monkeypatch.setattr(
        billing_store, "get_record_by_customer",
        lambda cid: (user_id, record),
    )
    upserted: list[dict] = []
    monkeypatch.setattr(
        billing_store, "upsert_record",
        lambda uid, **fields: upserted.append(fields),
    )
    return record, upserted


def test_evento_antiguo_no_reactiva_acceso(monkeypatch):
    billing = _billing_module()
    _record, upserted = _setup_customer_record(
        monkeypatch, status="canceled", last_event_created=2000
    )
    billing._sync_subscription_event(
        {"customer": "cus_test", "id": "sub_1", "status": "active"},
        event_created=1000,          # MAS ANTIGUO que el ultimo aplicado
        event_type="customer.subscription.updated",
    )
    assert upserted == []          # no se persistio nada: acceso no restaurado


def test_evento_reciente_aplica_normal(monkeypatch):
    billing = _billing_module()
    _record, upserted = _setup_customer_record(
        monkeypatch, status="canceled", last_event_created=1000
    )
    billing._sync_subscription_event(
        {"customer": "cus_test", "id": "sub_1", "status": "canceled"},
        event_created=2000,
        event_type="customer.subscription.deleted",
    )
    assert len(upserted) == 1
    assert upserted[0]["status"] == "canceled"


def test_estado_terminal_no_rebaja_a_activo(monkeypatch):
    billing = _billing_module()
    record, upserted = _setup_customer_record(monkeypatch, status="refunded")
    # El reembolso/cancelacion real deja memorizado el id terminal: una
    # reentrega de ESA suscripcion no se disfraza de contratacion nueva.
    record["last_canceled_subscription_id"] = "sub_1"
    billing._sync_subscription_event(
        {"customer": "cus_test", "id": "sub_1", "status": "active"},
        event_created=9999,          # reciente, PERO es la suscripcion terminal
        event_type="customer.subscription.updated",
    )
    assert upserted == []


def test_evento_sin_id_no_borra_suscripcion_guardada(monkeypatch):
    billing = _billing_module()
    record, upserted = _setup_customer_record(monkeypatch, status="active")
    record["stripe_subscription_id"] = "sub_9"
    billing._sync_subscription_event(
        {"customer": "cus_test", "status": "active"},  # sin "id"
        event_created=2000,
        event_type="customer.subscription.updated",
    )
    assert len(upserted) == 1
    assert "stripe_subscription_id" not in upserted[0]  # el id previo se conserva
    assert upserted[0]["status"] == "active"


# ============================================================
# Bloque D: reembolso total cancela la suscripcion
# ============================================================

def test_refund_total_cancela_suscripcion_activa(monkeypatch):
    billing = _billing_module()

    fake_sub = MagicMock()
    fake_sub.id = "sub_a_cancelar"
    list_result = MagicMock()
    list_result.get.return_value = [{"id": "sub_a_cancelar"}]

    monkeypatch.setattr(
        billing.stripe.Subscription, "list", lambda **kw: list_result
    )
    canceled: list[str] = []
    monkeypatch.setattr(
        billing.stripe.Subscription, "cancel", lambda sid: canceled.append(sid)
    )
    monkeypatch.setattr(
        billing.stripe.Refund, "create",
        lambda **kw: {"id": "re_test", "amount": 1600, "status": "succeeded"},
    )
    monkeypatch.setattr(
        billing, "_resolve_payment_to_charge",
        lambda client, pid: ("ch_test", "cus_test"),
    )
    # Cargo sin factura resoluble (pago sin vinculo de suscripcion):
    # aplica el cierre de activas del comportamiento vigente.
    monkeypatch.setattr(
        billing, "_resolve_subscription_for_charge",
        lambda client, cid: (None, True),
    )
    monkeypatch.setattr(billing, "get_stripe_client", lambda: MagicMock())

    from app.core import billing_store
    # Aislar del store real en disco: el reintento de pendientes corre
    # PRIMERO dentro de admin_refund y no debe tocar datos del entorno.
    monkeypatch.setattr(billing_store, "all_records", lambda: {})
    monkeypatch.setattr(
        billing_store, "get_record_by_customer", lambda cid: ("u1", {"status": "active"})
    )
    upserted: list[dict] = []
    monkeypatch.setattr(
        billing_store, "upsert_record", lambda uid, **f: upserted.append(f)
    )

    class Payload:
        reason = "requested_by_customer"
        payment_id = "ch_test"
        amount = None          # reembolso TOTAL

    import asyncio
    result = asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        billing.admin_refund(Payload(), admin=MagicMock())
    )
    assert result["canceled_subscriptions"] == ["sub_a_cancelar"]
    assert canceled == ["sub_a_cancelar"]
    assert any(f.get("status") == "refunded" for f in upserted)


# ============================================================
# Bloque D: espanol en patrones de phishing
# ============================================================

def test_patrones_espanol_detectan_urgencia():
    import asyncio

    from app.modules.content_analyzer.analyzer import ContentAnalyzer

    analyzer = ContentAnalyzer()
    result = asyncio.new_event_loop().run_until_complete(
        analyzer.analyze_content(
            "URGENTE: su cuenta será bloqueada. Verifique su cuenta haciendo clic aquí "
            "para confirmar su contraseña. Tiempo limitado.",
            "text",
        )
    )
    findings_text = str(result.get("findings", [])).lower()
    assert "urgency" in findings_text


def test_nlp_espanol_detecta_ingenieria_social():
    import asyncio

    from app.modules.ocr_nlp.analyzer import OCRNLPAnalyzer

    analyzer = OCRNLPAnalyzer()
    result = asyncio.new_event_loop().run_until_complete(
        analyzer.detect_social_engineering(
            "Felicidades, ganaste un premio. Ingrese su contraseña para reclamar "
            "su tarjeta de regalo. Su cuenta será suspendida si no responde ahora."
        )
    )
    assert result.get("score", 0) > 0


# ============================================================
# Validacion Codex: registro concurrente, re-suscripcion,
# cancelacion fallida y renovacion de sesion
# ============================================================

def test_registro_concurrente_solo_uno_gana(monkeypatch):
    """Dos registros simultaneos con el mismo username: uno 200, otro 400.
    Antes del fix, AMBOS daban 200 y el ultimo sobrescribia la identidad."""
    import asyncio

    from fastapi import HTTPException

    from app.api.routes import auth as auth_routes
    from app.core.auth import UserCreate, get_user, users_db

    async def do_register(username: str, email: str) -> str:
        try:
            await auth_routes.register(
                _request({}),
                UserCreate(username=username, email=email, password="Segura123!"),
            )
            return "200"
        except HTTPException as exc:
            return str(exc.status_code)

    async def main():
        return await asyncio.gather(
            do_register("raceuser", "race-a@example.com"),
            do_register("raceuser", "race-b@example.com"),
        )

    results = asyncio.new_event_loop().run_until_complete(main())
    try:
        assert sorted(results) == ["200", "400"], f"race condition: {results}"
        winner = get_user("raceuser")
        assert winner is not None
        # La identidad guardada corresponde a EXACTAMENTE una de las dos:
        assert winner.email in ("race-a@example.com", "race-b@example.com")
    finally:
        users_db.pop("raceuser", None)


def test_create_user_unique_rechaza_email_duplicado(monkeypatch):
    from app.core.auth import UserInDB, create_user_unique, users_db

    first = UserInDB(
        id="u1", username="dupuser", email="Dupe@Example.com",
        hashed_password="x",
    )
    created, reason = create_user_unique(first)
    assert created
    try:
        second = UserInDB(
            id="u2", username="otro", email="dupe@example.com",  # mismo, distinto case
            hashed_password="y",
        )
        created2, reason2 = create_user_unique(second)
        assert not created2 and reason2 == "email"
        third = UserInDB(
            id="u3", username="dupuser", email="nuevo@example.com",
            hashed_password="z",
        )
        created3, reason3 = create_user_unique(third)
        assert not created3 and reason3 == "username"
    finally:
        users_db.pop("dupuser", None)
        users_db.pop("otro", None)


def _patch_customer_record(monkeypatch, record: dict, upserted: list, user_id="u1"):
    from app.core import billing_store

    monkeypatch.setattr(
        billing_store, "get_record_by_customer", lambda cid: (user_id, record)
    )
    monkeypatch.setattr(
        billing_store, "upsert_record", lambda uid, **fields: upserted.append(fields)
    )
    return billing_store


def test_suscripcion_nueva_reactiva_tras_estado_terminal(monkeypatch):
    """Cancelada que vuelve a contratar: el evento de la NUEVA suscripcion
    (id distinto) debe aplicarse y otorgar acceso."""
    billing = _billing_module()
    record = {
        "status": "canceled",
        "stripe_customer_id": "cus_test",
        "stripe_subscription_id": "sub_old",
    }
    upserted: list[dict] = []
    _patch_customer_record(monkeypatch, record, upserted)

    billing._sync_subscription_event(
        {"customer": "cus_test", "id": "sub_new", "status": "active"},
        event_created=2000,
        event_type="customer.subscription.updated",
    )
    assert upserted, "la suscripcion nueva debe aplicarse"
    assert upserted[0]["status"] == "active"
    assert upserted[0]["stripe_subscription_id"] == "sub_new"
    assert upserted[0]["cancellation_pending"] is False


def test_misma_suscripcion_antigua_no_reactiva(monkeypatch):
    """La suscripcion VIEJA (mismo id) sigue sin poder reactivar una cuenta
    en estado terminal."""
    billing = _billing_module()
    record = {
        "status": "refunded",
        "stripe_customer_id": "cus_test",
        "stripe_subscription_id": "sub_old",
    }
    upserted: list[dict] = []
    _patch_customer_record(monkeypatch, record, upserted)

    billing._sync_subscription_event(
        {"customer": "cus_test", "id": "sub_old", "status": "active"},
        event_created=2000,
        event_type="customer.subscription.updated",
    )
    assert upserted == []


def test_reentrega_de_cancelada_no_aplica_con_id_perdido(monkeypatch):
    """Tras un reembolso total el store ya no guarda el id de suscripcion;
    sin ese ancla, last_canceled_subscription_id es lo que distingue una
    reentrega tardia (mismo id cancelado -> ignora) de una contratacion
    nueva (id distinto -> aplica)."""
    billing = _billing_module()
    record = {
        "status": "refunded",
        "stripe_customer_id": "cus_test",
        "stripe_subscription_id": None,
        "last_canceled_subscription_id": "sub_old",
    }
    upserted: list[dict] = []
    _patch_customer_record(monkeypatch, record, upserted)

    # Reentrega tardia de la suscripcion reembolsada: NO aplica.
    billing._sync_subscription_event(
        {"customer": "cus_test", "id": "sub_old", "status": "active"},
        event_created=2000,
        event_type="customer.subscription.updated",
    )
    assert upserted == []

    # Contratacion nueva con otro id: SI aplica y otorga acceso.
    billing._sync_subscription_event(
        {"customer": "cus_test", "id": "sub_new", "status": "active"},
        event_created=3000,
        event_type="customer.subscription.updated",
    )
    assert upserted and upserted[0]["status"] == "active"
    assert upserted[0]["stripe_subscription_id"] == "sub_new"


def test_refund_fallo_cancelacion_advierte_y_deja_pendiente(monkeypatch):
    """Si Stripe falla al cancelar tras un reembolso total: la respuesta
    debe advertirlo, conservar el subscription_id y marcar el pendiente."""
    billing = _billing_module()
    import stripe as stripe_lib

    monkeypatch.setattr(
        billing.stripe.Refund, "create",
        lambda **kw: {"id": "re_test", "amount": 1600, "status": "succeeded"},
    )
    monkeypatch.setattr(
        billing, "_resolve_payment_to_charge",
        lambda client, pid: ("ch_test", "cus_test"),
    )
    # Cargo sin factura resoluble (pago sin vinculo de suscripcion):
    # aplica el cierre de activas del comportamiento vigente.
    monkeypatch.setattr(
        billing, "_resolve_subscription_for_charge",
        lambda client, cid: (None, True),
    )
    monkeypatch.setattr(billing, "get_stripe_client", lambda: MagicMock())

    def _list_falla(**kw):
        raise stripe_lib.error.StripeError("fallo simulado de red")

    monkeypatch.setattr(billing.stripe.Subscription, "list", _list_falla)

    from app.core import billing_store

    monkeypatch.setattr(
        billing_store, "get_record_by_customer", lambda cid: ("u1", {"status": "active"})
    )
    upserted: list[dict] = []
    monkeypatch.setattr(
        billing_store, "upsert_record", lambda uid, **f: upserted.append(f)
    )
    monkeypatch.setattr(billing_store, "all_records", lambda: {})

    class Payload:
        reason = "requested_by_customer"
        payment_id = "ch_test"
        amount = None

    result = asyncio_run(billing.admin_refund(Payload(), admin=MagicMock()))

    assert result["status"] == "succeeded"            # el reembolso si se hizo
    assert "warning" in result                        # pero se advierte
    assert result["canceled_subscriptions"] == []
    refund_update = [f for f in upserted if f.get("status") == "refunded"]
    assert refund_update, "el estado local debe pasar a refunded"
    assert refund_update[0].get("cancellation_pending") is True
    assert "stripe_subscription_id" not in refund_update[0]  # se CONSERVA el id


def test_reintento_resuelve_cancelacion_pendiente(monkeypatch):
    """_retry_pending_cancellations cancela suscripciones activas de
    registros con cancellation_pending=True (idempotente, sin reembolsar)."""
    billing = _billing_module()

    from app.core import billing_store

    monkeypatch.setattr(billing_store, "all_records", lambda: {
        "u1": {
            "cancellation_pending": True,
            "stripe_customer_id": "cus_test",
            "stripe_subscription_id": "sub_pend",
        },
        "u2": {"cancellation_pending": False},
    })
    canceled: list[str] = []
    monkeypatch.setattr(
        billing.stripe.Subscription, "cancel", lambda sid: canceled.append(sid)
    )
    list_result = MagicMock()
    list_result.get.return_value = [{"id": "sub_pend"}]
    monkeypatch.setattr(
        billing.stripe.Subscription, "list", lambda **kw: list_result
    )
    upserted: list[dict] = []
    monkeypatch.setattr(
        billing_store, "upsert_record", lambda uid, **f: upserted.append(f)
    )

    billing._retry_pending_cancellations()

    assert canceled == ["sub_pend"]
    assert any(
        f.get("cancellation_pending") is False and f.get("stripe_subscription_id") is None
        for f in upserted
    )


def asyncio_run(coro):
    import asyncio

    return asyncio.new_event_loop().run_until_complete(coro)
