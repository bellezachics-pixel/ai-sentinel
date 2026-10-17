"""
Tests de billing (Stripe TEST). TODAS las llamadas a Stripe se mockean con
unittest.mock: sin red, sin claves reales, sin tocar la API de Stripe.
"""
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from conftest import API_PREFIX, make_user

from app.core import auth as auth_core
from app.core import billing_store
from app.core.billing import reset_stripe_client_for_tests
from app.core.config import settings

BILLING = f"{API_PREFIX}/billing"


@pytest.fixture()
def no_stripe(monkeypatch):
    """Garantiza modo 'sin pasarela' (503 en checkout)."""
    monkeypatch.setattr(settings, "STRIPE_SECRET_KEY", "")
    monkeypatch.setattr(settings, "STRIPE_WEBHOOK_SECRET", "")
    reset_stripe_client_for_tests()
    yield
    reset_stripe_client_for_tests()


@pytest.fixture()
def stripe_test(monkeypatch):
    """Claves Stripe TEST falsas (solo para ejercitar el codigo)."""
    monkeypatch.setattr(settings, "STRIPE_SECRET_KEY", "sk_test_falsa_solo_tests")
    monkeypatch.setattr(settings, "STRIPE_WEBHOOK_SECRET", "whsec_falso_solo_tests")
    monkeypatch.setattr(settings, "STRIPE_PRICE_ID", "price_falso_solo_tests")
    reset_stripe_client_for_tests()
    yield
    reset_stripe_client_for_tests()


def _user_id(username: str) -> str:
    return auth_core.get_user(username).id


def _expire_trial(username: str):
    """Retrocede el trial_start a hace 4 dias (trial vencido)."""
    user = auth_core.get_user(username)
    user.trial_start = datetime.utcnow() - timedelta(days=4)
    auth_core.users_db[username] = user
    auth_core._persist_users()


# ============================================================
# checkout
# ============================================================
def test_checkout_sin_clave_devuelve_503(client, auth_client, no_stripe):
    client, user = auth_client
    resp = client.post(f"{BILLING}/checkout", headers=user["headers"])
    assert resp.status_code == 503
    assert resp.json()["detail"] == "pasarela_no_configurada"


def test_checkout_con_stripe_mockeado_devuelve_url_y_luego_409(
    client, auth_client, stripe_test
):
    client, user = auth_client
    with (
        patch("stripe.Customer.list", return_value={"data": []}),
        patch("stripe.Customer.create", return_value={"id": "cus_test_1"}),
        patch(
            "stripe.checkout.Session.create",
            return_value={"id": "cs_test_1", "url": "https://checkout.stripe.com/pay/test"},
        ),
    ):
        resp = client.post(f"{BILLING}/checkout", headers=user["headers"])
        assert resp.status_code == 200, resp.text
        assert resp.json()["checkout_url"].startswith("https://checkout.stripe.com/")

    # Segunda llamada con suscripcion ya activa en el store -> 409.
    billing_store.upsert_record(
        _user_id(user["username"]),
        stripe_customer_id="cus_test_1",
        stripe_subscription_id="sub_test_1",
        status="active",
    )
    resp = client.post(f"{BILLING}/checkout", headers=user["headers"])
    assert resp.status_code == 409


# ============================================================
# portal
# ============================================================
def test_portal_sin_cliente_devuelve_404(client, auth_client, stripe_test):
    client, user = auth_client
    resp = client.post(f"{BILLING}/portal", headers=user["headers"])
    assert resp.status_code == 404


def test_portal_con_cliente_devuelve_url(client, auth_client, stripe_test):
    client, user = auth_client
    billing_store.upsert_record(
        _user_id(user["username"]), stripe_customer_id="cus_test_1"
    )
    with patch(
        "stripe.billing_portal.Session.create",
        return_value={"url": "https://billing.stripe.com/session/test"},
    ):
        resp = client.post(f"{BILLING}/portal", headers=user["headers"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["portal_url"].startswith("https://billing.stripe.com/")


# ============================================================
# status
# ============================================================
def test_status_usuario_nuevo_trial_activo(client, auth_client, no_stripe):
    client, user = auth_client
    resp = client.get(f"{BILLING}/status", headers=user["headers"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["has_access"] is True
    # Sin suscripcion Stripe pero con trial local vivo se reporta "trialing"
    # para que la UI muestre el contador de dias restantes.
    assert data["status"] == "trialing"
    assert data["trial_end"] is not None
    assert data["current_period_end"] is None
    assert data["cancel_at_period_end"] is False
    assert data["plan_price"] == "US$16/mes"


@pytest.mark.parametrize("sub_status", ["trialing", "active"])
def test_status_con_suscripcion_otorga_acceso(client, auth_client, stripe_test, sub_status):
    client, user = auth_client
    _expire_trial(user["username"])  # sin trial: solo la suscripcion cuenta
    billing_store.upsert_record(
        _user_id(user["username"]),
        stripe_customer_id="cus_test_1",
        stripe_subscription_id="sub_test_1",
        status=sub_status,
        trial_end="2030-01-01T00:00:00+00:00",
        current_period_end="2030-01-01T00:00:00+00:00",
        cancel_at_period_end=False,
    )
    resp = client.get(f"{BILLING}/status", headers=user["headers"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["has_access"] is True
    assert data["status"] == sub_status
    assert data["trial_end"] == "2030-01-01T00:00:00+00:00"
    assert data["current_period_end"] == "2030-01-01T00:00:00+00:00"


def test_status_trial_vencido_sin_suscripcion_sin_acceso(client, auth_client, no_stripe):
    client, user = auth_client
    _expire_trial(user["username"])
    resp = client.get(f"{BILLING}/status", headers=user["headers"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["has_access"] is False
    assert data["status"] == "none"


# ============================================================
# webhook
# ============================================================
def test_webhook_sin_secreto_devuelve_503(client, no_stripe):
    resp = client.post(
        f"{BILLING}/webhook",
        content=b"{}",
        headers={"Stripe-Signature": "t=1,v1=x"},
    )
    assert resp.status_code == 503
    assert resp.json()["detail"] == "pasarela_no_configurada"


def test_webhook_firma_invalida_devuelve_400(client, stripe_test):
    # construct_event real (sin red): la firma no coincide con el secreto.
    resp = client.post(
        f"{BILLING}/webhook",
        content=b'{"id":"evt_1","type":"ping"}',
        headers={"Stripe-Signature": "t=1700000000,v1=firma_falsa"},
    )
    assert resp.status_code == 400


def test_webhook_checkout_completed_actualiza_store(client, stripe_test, auth_client):
    client, user = auth_client
    user_id = _user_id(user["username"])
    event = {
        "id": "evt_test_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_1",
                "customer": "cus_test_1",
                "subscription": "sub_test_1",
                "metadata": {"user_id": user_id},
            }
        },
    }
    with patch("stripe.Webhook.construct_event", return_value=event):
        resp = client.post(
            f"{BILLING}/webhook",
            content=b'{"id":"evt_test_1"}',
            headers={"Stripe-Signature": "t=1,v1=valida_mockeada"},
        )
    assert resp.status_code == 200
    assert resp.json() == {"received": True}
    record = billing_store.get_record(user_id)
    assert record["stripe_customer_id"] == "cus_test_1"
    assert record["stripe_subscription_id"] == "sub_test_1"
    assert record["status"] == "trialing"


def test_webhook_subscription_updated_sincroniza_estado(client, stripe_test, auth_client):
    client, user = auth_client
    user_id = _user_id(user["username"])
    billing_store.upsert_record(user_id, stripe_customer_id="cus_test_2")
    event = {
        "id": "evt_test_2",
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_test_2",
                "customer": "cus_test_2",
                "status": "active",
                "trial_end": 1893456000,  # 2030-01-01T00:00:00Z
                "current_period_end": 1893456000,
                "cancel_at_period_end": True,
            }
        },
    }
    with patch("stripe.Webhook.construct_event", return_value=event):
        resp = client.post(
            f"{BILLING}/webhook",
            content=b'{"id":"evt_test_2"}',
            headers={"Stripe-Signature": "t=1,v1=valida_mockeada"},
        )
    assert resp.status_code == 200
    record = billing_store.get_record(user_id)
    assert record["status"] == "active"
    assert record["cancel_at_period_end"] is True
    assert record["current_period_end"].startswith("2030-01-01")


# ============================================================
# Enforcement (402) en /analyze/url
# ============================================================
def test_analyze_url_usuario_trial_vencido_devuelve_402(client, auth_client):
    client, user = auth_client
    _expire_trial(user["username"])
    resp = client.post(
        f"{API_PREFIX}/analyze/url",
        json={"url": "https://example.com/login"},
        headers=user["headers"],
    )
    assert resp.status_code == 402
    assert resp.json()["detail"] == "trial_expirado_o_suscripcion_requerida"


def test_analyze_url_usuario_trial_activo_devuelve_200(client, auth_client):
    client, user = auth_client
    resp = client.post(
        f"{API_PREFIX}/analyze/url",
        json={"url": "https://example.com/login"},
        headers=user["headers"],
    )
    assert resp.status_code == 200


def test_analyze_url_suscripcion_activa_con_trial_vencido_devuelve_200(
    client, auth_client, stripe_test
):
    client, user = auth_client
    _expire_trial(user["username"])
    billing_store.upsert_record(
        _user_id(user["username"]),
        stripe_customer_id="cus_test_1",
        stripe_subscription_id="sub_test_1",
        status="active",
    )
    resp = client.post(
        f"{API_PREFIX}/analyze/url",
        json={"url": "https://example.com/login"},
        headers=user["headers"],
    )
    assert resp.status_code == 200


def test_analyze_url_anonimo_sigue_permitido(client):
    # REQUIRE_AUTH_FOR_ANALYSIS=false: sin usuario no hay chequeo de acceso.
    resp = client.post(
        f"{API_PREFIX}/analyze/url",
        json={"url": "https://example.com/login"},
    )
    assert resp.status_code == 200


# ============================================================
# webhook: reembolsos y confirmaciones de pago
# ============================================================
def _post_webhook_mocked(client, event):
    with patch("stripe.Webhook.construct_event", return_value=event):
        return client.post(
            f"{BILLING}/webhook",
            content=b'{"id":"evt_x"}',
            headers={"Stripe-Signature": "t=1,v1=valida_mockeada"},
        )


def test_webhook_charge_refunded_total_marca_reembolsado_sin_acceso(
    client, stripe_test, auth_client
):
    from app.core.billing import has_access, trial_active

    client, user = auth_client
    user_id = _user_id(user["username"])
    billing_store.upsert_record(
        user_id,
        stripe_customer_id="cus_r",
        stripe_subscription_id="sub_r",
        status="active",
    )
    event = {
        "id": "evt_refund_1",
        "type": "charge.refunded",
        "data": {
            "object": {
                "id": "ch_r",
                "customer": "cus_r",
                "amount": 1600,
                "amount_refunded": 1600,
            }
        },
    }
    resp = _post_webhook_mocked(client, event)
    assert resp.status_code == 200

    record = billing_store.get_record(user_id)
    assert record["status"] == "refunded"
    assert record["stripe_subscription_id"] is None
    assert record["last_refund_amount"] == 1600
    assert record["last_refund_at"] is not None

    # El trial local sigue vivo, pero NO resucita el acceso tras el reembolso.
    usuario = auth_core.get_user(user["username"])
    assert trial_active(usuario) is True
    assert has_access(usuario, record) is False


def test_webhook_charge_refunded_parcial_no_cambia_estado(
    client, stripe_test, auth_client
):
    client, user = auth_client
    user_id = _user_id(user["username"])
    billing_store.upsert_record(
        user_id, stripe_customer_id="cus_rp", status="active"
    )
    event = {
        "id": "evt_refund_2",
        "type": "charge.refunded",
        "data": {
            "object": {
                "id": "ch_rp",
                "customer": "cus_rp",
                "amount": 1600,
                "amount_refunded": 400,
            }
        },
    }
    resp = _post_webhook_mocked(client, event)
    assert resp.status_code == 200

    record = billing_store.get_record(user_id)
    assert record["status"] == "active"  # reembolso parcial: sigue activo
    assert record["last_refund_amount"] == 400


def test_webhook_invoice_payment_succeeded_guarda_ultimo_pago(
    client, stripe_test, auth_client
):
    client, user = auth_client
    user_id = _user_id(user["username"])
    billing_store.upsert_record(user_id, stripe_customer_id="cus_p")
    event = {
        "id": "evt_pay_1",
        "type": "invoice.payment_succeeded",
        "data": {
            "object": {
                "id": "in_1",
                "customer": "cus_p",
                "subscription": "sub_p",
                "amount_paid": 1600,
                "period_end": 1893456000,  # 2030-01-01T00:00:00Z
            }
        },
    }
    resp = _post_webhook_mocked(client, event)
    assert resp.status_code == 200

    record = billing_store.get_record(user_id)
    assert record["last_payment_amount"] == 1600
    assert record["last_payment_at"] is not None
    assert record["current_period_end"].startswith("2030-01-01")


# ============================================================
# has_access: refunded / canceled bloquean aun con trial vivo
# ============================================================
@pytest.mark.parametrize("sub_status", ["refunded", "canceled"])
def test_has_access_reembolsado_o_cancelado_bloquea_trial_activo(
    client, auth_client, stripe_test, sub_status
):
    from app.core.billing import has_access, trial_active

    client, user = auth_client
    usuario = auth_core.get_user(user["username"])
    assert trial_active(usuario) is True  # trial local vigente
    assert has_access(usuario, {"status": sub_status}) is False


@pytest.mark.parametrize("sub_status", ["refunded", "canceled"])
def test_has_access_reembolsado_bloquea_en_modo_trial_only(
    client, auth_client, no_stripe, sub_status
):
    from app.core.billing import has_access, trial_active

    client, user = auth_client
    usuario = auth_core.get_user(user["username"])
    assert trial_active(usuario) is True
    assert has_access(usuario, {"status": sub_status}) is False


# ============================================================
# admin: reembolso administrativo
# ============================================================
def _make_admin(username: str = "admin_reembolsos") -> dict:
    """Crea un usuario admin (is_admin=True) con JWT propio, sin panel admin."""
    auth_core.users_db[username] = auth_core.UserInDB(
        id=f"id-{username}",
        username=username,
        email=f"{username}@example.com",
        hashed_password=auth_core.hash_password("Admin123!x"),
        is_active=True,
        is_admin=True,
    )
    auth_core._persist_users()
    token = auth_core.create_access_token({"sub": username})
    return {"username": username, "headers": {"Authorization": f"Bearer {token}"}}


def test_admin_refund_no_admin_devuelve_403(client, auth_client, stripe_test):
    client, user = auth_client
    resp = client.post(
        f"{BILLING}/admin/refund",
        json={"payment_id": "ch_x"},
        headers=user["headers"],
    )
    assert resp.status_code == 403


def test_admin_refund_motivo_invalido_devuelve_400(client, stripe_test):
    admin = _make_admin()
    resp = client.post(
        f"{BILLING}/admin/refund",
        json={"payment_id": "ch_x", "reason": "sin_ganas"},
        headers=admin["headers"],
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "motivo_reembolso_invalido"


def test_admin_refund_sin_stripe_devuelve_503(client, no_stripe):
    admin = _make_admin()
    resp = client.post(
        f"{BILLING}/admin/refund",
        json={"payment_id": "ch_x"},
        headers=admin["headers"],
    )
    assert resp.status_code == 503
    assert resp.json()["detail"] == "pasarela_no_configurada"


def test_admin_refund_error_stripe_devuelve_502(client, stripe_test):
    import stripe

    admin = _make_admin()
    with (
        patch(
            "stripe.Charge.retrieve",
            return_value={"id": "ch_x", "customer": "cus_x"},
        ),
        patch(
            "stripe.Refund.create",
            side_effect=stripe.error.StripeError("fallo_test"),
        ),
    ):
        resp = client.post(
            f"{BILLING}/admin/refund",
            json={"payment_id": "ch_x"},
            headers=admin["headers"],
        )
    assert resp.status_code == 502
    assert resp.json()["detail"] == "error_pasarela_pago"


def test_admin_refund_con_sesion_cs_resuelve_y_registra_localmente(
    client, stripe_test
):
    admin = _make_admin()
    admin_user = auth_core.get_user(admin["username"])
    billing_store.upsert_record(
        admin_user.id, stripe_customer_id="cus_admin"
    )
    with (
        patch(
            "stripe.checkout.Session.retrieve",
            return_value={"id": "cs_x", "payment_intent": "pi_x"},
        ),
        patch(
            "stripe.Charge.list",
            return_value={"data": [{"id": "ch_x", "customer": "cus_admin"}]},
        ),
        patch(
            "stripe.Refund.create",
            return_value={"id": "re_x", "amount": 1600, "status": "succeeded"},
        ),
    ):
        resp = client.post(
            f"{BILLING}/admin/refund",
            json={"payment_id": "cs_x", "reason": "requested_by_customer"},
            headers=admin["headers"],
        )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["refund_id"] == "re_x"
    assert data["amount"] == 1600
    assert data["status"] == "succeeded"

    record = billing_store.get_record(admin_user.id)
    assert record["last_refund_id"] == "re_x"
    assert record["last_refund_amount"] == 1600
    assert record["last_refund_at"] is not None


def test_is_admin_user_por_email_admin_emails(client, auth_client, monkeypatch):
    # Sin is_admin ni ADMIN_EMAILS: no es admin (403).
    client, user = auth_client
    u = auth_core.get_user(user["username"])
    assert auth_core.is_admin_user(u) is False
    # Con su email en ADMIN_EMAILS: pasa el chequeo de admin (cae en 503
    # por falta de pasarela, no en 403).
    monkeypatch.setattr(settings, "ADMIN_EMAILS", f"otro@example.com,{u.email}")
    assert auth_core.is_admin_user(u) is True
    resp = client.post(
        f"{BILLING}/admin/refund",
        json={"payment_id": "ch_x"},
        headers=user["headers"],
    )
    assert resp.status_code == 503


# ============================================================
# GET /api/v1/billing/payments
# ============================================================
def test_payments_sin_stripe_devuelve_503(client, auth_client, no_stripe):
    client, user = auth_client
    resp = client.get(f"{BILLING}/payments", headers=user["headers"])
    assert resp.status_code == 503
    assert resp.json()["detail"] == "pasarela_no_configurada"


def test_payments_sin_customer_devuelve_lista_vacia(client, auth_client, stripe_test):
    client, user = auth_client
    resp = client.get(f"{BILLING}/payments", headers=user["headers"])
    assert resp.status_code == 200
    assert resp.json() == {"payments": []}


def test_payments_lista_cargos_mockeados_mas_recientes_primero(
    client, auth_client, stripe_test
):
    client, user = auth_client
    user_id = _user_id(user["username"])
    billing_store.upsert_record(user_id, stripe_customer_id="cus_pay")
    charges = {
        "data": [
            {
                "id": "ch_viejo",
                "amount": 1600,
                "currency": "usd",
                "status": "succeeded",
                "description": "CENTINELA Pro",
                "created": 1700000000,
                "receipt_url": "https://pay.stripe.com/receipt_viejo",
            },
            {
                "id": "ch_nuevo",
                "amount": 1600,
                "currency": "usd",
                "status": "succeeded",
                "description": "CENTINELA Pro",
                "created": 1893456000,  # 2030-01-01
                "receipt_url": "https://pay.stripe.com/receipt_nuevo",
            },
        ]
    }
    with patch("stripe.Charge.list", return_value=charges):
        resp = client.get(f"{BILLING}/payments", headers=user["headers"])
    assert resp.status_code == 200, resp.text
    payments = resp.json()["payments"]
    assert len(payments) == 2
    # Mas reciente primero, con la forma exacta del contrato.
    assert payments[0]["id"] == "ch_nuevo"
    assert payments[0]["date"].startswith("2030-01-01")
    for item in payments:
        assert set(item.keys()) == {
            "id",
            "amount",
            "currency",
            "status",
            "description",
            "date",
            "receipt_url",
        }
