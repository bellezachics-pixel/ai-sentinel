"""
Frente 3 (Stripe y datos): recorrido completo de clienta nueva.

Integracion de extremo a extremo con TestClient y Stripe 100% mockeado
(unittest.mock): sin red, sin claves reales, sin tocar la API de Stripe.

Cubre el ciclo de vida completo:
(a) registro con trial de 3 dias y acceso
(b) trial vencido sin suscripcion -> sin acceso (402)
(c) checkout crea sesion
(d) webhook checkout.session.completed -> trialing + acceso
(e) webhook customer.subscription.deleted -> sin acceso
(f) nuevo checkout tras cancelar + webhook de la nueva suscripcion activa
    -> acceso restaurado (incluye el checkout.session.completed protegido)
(g) reembolso total admin con cancelacion exitosa -> refunded, sin acceso
(h) reembolso total con fallo de cancelacion -> warning + pending durable
(i) siguiente admin_refund: el retry resuelve el pendiente
(j) evento webhook antiguo (created menor) no restaura acceso
(k) users.json corrupto -> cuarentena y load_users devuelve {}
"""
from datetime import timedelta
from unittest.mock import patch

import pytest
import stripe as stripe_lib

from conftest import API_PREFIX, make_user

from app.core import auth as auth_core
from app.core import billing_store, user_store
from app.core.billing import reset_stripe_client_for_tests, trial_end_for
from app.core.config import settings

BILLING = f"{API_PREFIX}/billing"
ANALYZE_URL = f"{API_PREFIX}/analyze/url"


@pytest.fixture()
def stripe_test(monkeypatch):
    """Claves Stripe TEST falsas (solo para ejercitar el codigo)."""
    monkeypatch.setattr(settings, "STRIPE_SECRET_KEY", "sk_test_falsa_solo_tests")
    monkeypatch.setattr(settings, "STRIPE_WEBHOOK_SECRET", "whsec_falso_solo_tests")
    monkeypatch.setattr(settings, "STRIPE_PRICE_ID", "price_falso_solo_tests")
    reset_stripe_client_for_tests()
    yield
    reset_stripe_client_for_tests()


@pytest.fixture()
def sin_pendientes_ajenos():
    """Aísla el retry durable: ningun registro ajeno queda con
    cancellation_pending (los tests de otros archivos pueden haberlo marcado)."""
    for uid, rec in billing_store.all_records().items():
        if rec.get("cancellation_pending"):
            billing_store.upsert_record(uid, cancellation_pending=False)


def _headers(user: dict) -> dict:
    return {"Authorization": f"Bearer {user['access']}"}


def _user_id(username: str) -> str:
    return auth_core.get_user(username).id


def _expire_trial(username: str):
    """Retrocede el trial_start a hace 4 dias (trial vencido)."""
    user = auth_core.get_user(username)
    user.trial_start = user.trial_start - timedelta(days=4)
    auth_core.users_db[username] = user
    auth_core._persist_users()


def _post_webhook(client, event: dict):
    with patch("stripe.Webhook.construct_event", return_value=event):
        return client.post(
            f"{BILLING}/webhook",
            content=b'{"id":"evt"}',
            headers={"Stripe-Signature": "t=1,v1=firma_mockeada"},
        )


def _checkout_session_mock(customer_id: str, session_id: str, url: str):
    """Mocks para POST /billing/checkout (Customer + Session.create)."""
    return (
        patch("stripe.Customer.list", return_value={"data": []}),
        patch("stripe.Customer.create", return_value={"id": customer_id}),
        patch(
            "stripe.checkout.Session.create",
            return_value={"id": session_id, "url": url},
        ),
    )


def _suscribir_activa(client, username: str, customer_id: str, sub_id: str,
                      event_id: str, created: int):
    """ webhook checkout.session.completed -> customer.subscription.updated(active)."""
    user_id = _user_id(username)
    resp = _post_webhook(client, {
        "id": f"{event_id}_checkout",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": f"cs_{sub_id}", "customer": customer_id,
            "subscription": sub_id, "metadata": {"user_id": user_id},
        }},
    })
    assert resp.status_code == 200, resp.text
    resp = _post_webhook(client, {
        "id": f"{event_id}_updated",
        "type": "customer.subscription.updated",
        "created": created,
        "data": {"object": {
            "id": sub_id, "customer": customer_id, "status": "active",
            "current_period_end": 1893456000,  # 2030-01-01
        }},
    })
    assert resp.status_code == 200, resp.text
    record = billing_store.get_record(user_id)
    assert record["status"] == "active"
    return record


def _make_admin(username: str = "admin_frente3") -> dict:
    auth_core.users_db[username] = auth_core.UserInDB(
        id=f"id-{username}", username=username,
        email=f"{username}@example.com",
        hashed_password=auth_core.hash_password("Admin123!x"),
        is_active=True, is_admin=True,
    )
    auth_core._persist_users()
    token = auth_core.create_access_token({"sub": username})
    return {"username": username, "headers": {"Authorization": f"Bearer {token}"}}


def _has_access(client, headers) -> bool:
    resp = client.get(f"{BILLING}/status", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["has_access"]


def _analyze_status(client, headers) -> int:
    return client.post(
        f"{ANALYZE_URL}", json={"url": "https://example.com/login"},
        headers=headers,
    ).status_code


# ============================================================
# Recorrido (a)-(f): trial, checkout, suscripcion, cancelacion
# y recontratacion
# ============================================================

def test_recorrido_trial_checkout_suscripcion_cancelacion_y_recontratacion(
    client, stripe_test
):
    user = make_user(client, "clienta_f3_recorrido")
    headers = _headers(user)
    username = user["username"]
    user_id = _user_id(username)

    # (a) Se registra: trial de 3 dias con acceso.
    assert _has_access(client, headers) is True
    usuario = auth_core.get_user(username)
    assert usuario.trial_start is not None
    assert trial_end_for(usuario) - usuario.trial_start == timedelta(days=3)
    assert _analyze_status(client, headers) == 200

    # (b) Trial vencido SIN suscripcion = sin acceso (402 en analisis).
    _expire_trial(username)
    assert _has_access(client, headers) is False
    assert _analyze_status(client, headers) == 402

    # (c) Checkout crea sesion.
    p1, p2, p3 = _checkout_session_mock(
        "cus_f3_rec", "cs_f3_rec", "https://checkout.stripe.com/pay/f3_rec"
    )
    with p1, p2, p3:
        resp = client.post(f"{BILLING}/checkout", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["checkout_url"].startswith("https://checkout.stripe.com/")

    # (d) Webhook checkout.session.completed -> trialing y hay acceso
    # (aunque el trial local este vencido).
    resp = _post_webhook(client, {
        "id": "evt_f3_rec_1",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_f3_rec", "customer": "cus_f3_rec",
            "subscription": "sub_f3_rec_1", "metadata": {"user_id": user_id},
        }},
    })
    assert resp.status_code == 200, resp.text
    record = billing_store.get_record(user_id)
    assert record["status"] == "trialing"
    assert record["stripe_customer_id"] == "cus_f3_rec"
    assert _has_access(client, headers) is True
    assert _analyze_status(client, headers) == 200

    # (e) Webhook customer.subscription.deleted -> sin acceso.
    resp = _post_webhook(client, {
        "id": "evt_f3_rec_2",
        "type": "customer.subscription.deleted",
        "created": 2500,
        "data": {"object": {
            "id": "sub_f3_rec_1", "customer": "cus_f3_rec", "status": "canceled",
        }},
    })
    assert resp.status_code == 200, resp.text
    record = billing_store.get_record(user_id)
    assert record["status"] == "canceled"
    assert _has_access(client, headers) is False
    assert _analyze_status(client, headers) == 402

    # (f) NUEVO checkout tras cancelar: el checkout.session.completed de la
    # nueva sesion NO pisa el estado protegido "canceled"; el webhook de la
    # NUEVA suscripcion activa (id distinto) es el que restaura el acceso.
    with patch(
        "stripe.checkout.Session.create",
        return_value={
            "id": "cs_f3_rec_2",
            "url": "https://checkout.stripe.com/pay/f3_rec_2",
        },
    ):
        resp = client.post(f"{BILLING}/checkout", headers=headers)
    assert resp.status_code == 200, resp.text

    resp = _post_webhook(client, {
        "id": "evt_f3_rec_3",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_f3_rec_2", "customer": "cus_f3_rec",
            "subscription": "sub_f3_rec_2", "metadata": {"user_id": user_id},
        }},
    })
    assert resp.status_code == 200, resp.text
    assert billing_store.get_record(user_id)["status"] == "canceled"  # protegido

    resp = _post_webhook(client, {
        "id": "evt_f3_rec_4",
        "type": "customer.subscription.updated",
        "created": 3000,
        "data": {"object": {
            "id": "sub_f3_rec_2", "customer": "cus_f3_rec", "status": "active",
            "current_period_end": 1893456000,
        }},
    })
    assert resp.status_code == 200, resp.text
    record = billing_store.get_record(user_id)
    assert record["status"] == "active"
    assert record["stripe_subscription_id"] == "sub_f3_rec_2"
    assert _has_access(client, headers) is True
    assert _analyze_status(client, headers) == 200


# ============================================================
# Recorrido (g) + (j): reembolso total admin y evento antiguo
# ============================================================

def test_recorrido_reembolso_total_admin_y_evento_antiguo(
    client, stripe_test, sin_pendientes_ajenos
):
    user = make_user(client, "clienta_f3_reembolso")
    headers = _headers(user)
    username = user["username"]
    user_id = _user_id(username)
    admin = _make_admin()

    _expire_trial(username)
    p1, p2, p3 = _checkout_session_mock(
        "cus_f3_ref", "cs_f3_ref", "https://checkout.stripe.com/pay/f3_ref"
    )
    with p1, p2, p3:
        resp = client.post(f"{BILLING}/checkout", headers=headers)
    assert resp.status_code == 200, resp.text
    _suscribir_activa(client, username, "cus_f3_ref", "sub_f3_ref_1",
                      "evt_f3_ref", 2500)
    assert _has_access(client, headers) is True

    def _subs_por_customer(**kw):
        if kw.get("customer") == "cus_f3_ref":
            return {"data": [{"id": "sub_f3_ref_1"}]}
        return {"data": []}

    canceled: list[str] = []

    # (g) Reembolso TOTAL con cancelacion exitosa: refunded, sin acceso y la
    # suscripcion remota cancelada.
    with (
        patch("stripe.Charge.retrieve",
              return_value={"id": "ch_f3_ref", "customer": "cus_f3_ref"}),
        patch("stripe.Refund.create",
              return_value={"id": "re_f3_ref", "amount": 1600, "status": "succeeded"}),
        patch("stripe.Subscription.list", side_effect=_subs_por_customer),
        patch("stripe.Subscription.cancel",
              side_effect=lambda sid: canceled.append(sid)),
    ):
        resp = client.post(
            f"{BILLING}/admin/refund",
            json={"payment_id": "ch_f3_ref", "reason": "requested_by_customer"},
            headers=admin["headers"],
        )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "succeeded"
    assert data["refund_id"] == "re_f3_ref"
    assert data["canceled_subscriptions"] == ["sub_f3_ref_1"]
    assert "warning" not in data
    assert canceled == ["sub_f3_ref_1"]

    record = billing_store.get_record(user_id)
    assert record["status"] == "refunded"
    assert record["stripe_subscription_id"] is None
    assert record["cancellation_pending"] is False
    assert record["last_canceled_subscription_id"] == "sub_f3_ref_1"
    assert record["last_refund_id"] == "re_f3_ref"
    assert _has_access(client, headers) is False
    assert _analyze_status(client, headers) == 402

    # (j) Evento webhook ANTIGUO (created menor) no restaura acceso.
    resp = _post_webhook(client, {
        "id": "evt_f3_ref_old",
        "type": "customer.subscription.updated",
        "created": 2000,  # < 2500 (ultimo evento aplicado)
        "data": {"object": {
            "id": "sub_f3_ref_1", "customer": "cus_f3_ref", "status": "active",
        }},
    })
    assert resp.status_code == 200, resp.text
    assert billing_store.get_record(user_id)["status"] == "refunded"
    assert _has_access(client, headers) is False

    # Reentrega TARDIA de la suscripcion reembolsada (created mayor) tampoco
    # aplica: el id coincide con last_canceled_subscription_id.
    resp = _post_webhook(client, {
        "id": "evt_f3_ref_replay",
        "type": "customer.subscription.updated",
        "created": 9999,
        "data": {"object": {
            "id": "sub_f3_ref_1", "customer": "cus_f3_ref", "status": "active",
        }},
    })
    assert resp.status_code == 200, resp.text
    assert billing_store.get_record(user_id)["status"] == "refunded"
    assert _has_access(client, headers) is False


# ============================================================
# Recorrido (h) + (i): cancelacion fallida -> pendiente durable ->
# retry idempotente al siguiente admin_refund
# ============================================================

def test_recorrido_reembolso_fallo_cancelacion_retry_resuelve_y_recontratacion(
    client, stripe_test, sin_pendientes_ajenos
):
    user = make_user(client, "clienta_f3_fallo")
    headers = _headers(user)
    username = user["username"]
    user_id = _user_id(username)
    admin = _make_admin("admin_frente3_fallo")

    _expire_trial(username)
    p1, p2, p3 = _checkout_session_mock(
        "cus_f3_fl", "cs_f3_fl", "https://checkout.stripe.com/pay/f3_fl"
    )
    with p1, p2, p3:
        resp = client.post(f"{BILLING}/checkout", headers=headers)
    assert resp.status_code == 200, resp.text
    _suscribir_activa(client, username, "cus_f3_fl", "sub_f3_fl_1",
                      "evt_f3_fl", 2600)

    def _list_falla(**kw):
        raise stripe_lib.error.StripeError("fallo simulado de red")

    # (h) Reembolso TOTAL con FALLO de cancelacion: warning explicito,
    # cancellation_pending durable y subscription_id CONSERVADO.
    with (
        patch("stripe.Charge.retrieve",
              return_value={"id": "ch_f3_fl", "customer": "cus_f3_fl"}),
        patch("stripe.Refund.create",
              return_value={"id": "re_f3_fl_1", "amount": 1600, "status": "succeeded"}),
        patch("stripe.Subscription.list", side_effect=_list_falla),
    ):
        resp = client.post(
            f"{BILLING}/admin/refund",
            json={"payment_id": "ch_f3_fl", "reason": "requested_by_customer"},
            headers=admin["headers"],
        )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "succeeded"      # el reembolso SI se hizo
    assert "warning" in data                  # pero se advierte el riesgo
    assert data["cancellation_error"]
    assert data["canceled_subscriptions"] == []

    record = billing_store.get_record(user_id)
    assert record["status"] == "refunded"
    assert record["cancellation_pending"] is True
    assert record["stripe_subscription_id"] == "sub_f3_fl_1"  # conservado

    # (i) Al SIGUIENTE admin_refund el retry resuelve el pendiente: cancela
    # la suscripcion activa remota y limpia el estado local.
    canceled: list[str] = []

    def _subs_activas(**kw):
        if kw.get("customer") == "cus_f3_fl":
            return {"data": [{"id": "sub_f3_fl_1"}]}
        return {"data": []}

    with (
        patch("stripe.Charge.retrieve",
              return_value={"id": "ch_f3_fl", "customer": "cus_f3_fl"}),
        patch("stripe.Refund.create",
              return_value={"id": "re_f3_fl_2", "amount": 100, "status": "succeeded"}),
        patch("stripe.Subscription.list", side_effect=_subs_activas),
        patch("stripe.Subscription.cancel",
              side_effect=lambda sid: canceled.append(sid)),
    ):
        resp = client.post(
            f"{BILLING}/admin/refund",
            json={"payment_id": "ch_f3_fl", "reason": "requested_by_customer",
                  "amount": 100},  # parcial: el retry es quien cierra el pendiente
            headers=admin["headers"],
        )
    assert resp.status_code == 200, resp.text
    assert canceled == ["sub_f3_fl_1"]

    record = billing_store.get_record(user_id)
    assert record["cancellation_pending"] is False
    assert record["stripe_subscription_id"] is None
    assert record["last_canceled_subscription_id"] == "sub_f3_fl_1"
    assert record["last_refund_id"] == "re_f3_fl_2"
    assert _has_access(client, headers) is False

    # Recontratacion REAL tras el reembolso total (subscription_id ya en
    # None): la suscripcion nueva con id distinto aplica y restaura acceso.
    resp = _post_webhook(client, {
        "id": "evt_f3_fl_new",
        "type": "customer.subscription.updated",
        "created": 2700,
        "data": {"object": {
            "id": "sub_f3_fl_2", "customer": "cus_f3_fl", "status": "active",
            "current_period_end": 1893456000,
        }},
    })
    assert resp.status_code == 200, resp.text
    record = billing_store.get_record(user_id)
    assert record["status"] == "active"
    assert record["stripe_subscription_id"] == "sub_f3_fl_2"
    assert _has_access(client, headers) is True


# ============================================================
# Recorrido (k): users.json corrupto -> cuarentena
# ============================================================

def test_users_json_corrupto_va_a_cuarentena_y_load_devuelve_vacio(client):
    original = (
        user_store.USERS_FILE.read_text(encoding="utf-8")
        if user_store.USERS_FILE.exists()
        else None
    )
    try:
        user_store.USERS_FILE.write_text("{json completamente roto", encoding="utf-8")

        users = user_store.load_users()
        assert users == {}  # no explota: devuelve vacio sin sobrescribir

        quarantined = list(user_store.DATA_DIR.glob("users.json.corrupt-*"))
        assert quarantined, "el archivo corrupto debe moverse a cuarentena"
        # El original ya no queda con el contenido corrupto en su lugar.
        assert not user_store.USERS_FILE.exists()
    finally:
        for q in user_store.DATA_DIR.glob("users.json.corrupt-*"):
            q.unlink(missing_ok=True)
        if original is not None:
            user_store.USERS_FILE.write_text(original, encoding="utf-8")
        else:
            user_store.USERS_FILE.unlink(missing_ok=True)
