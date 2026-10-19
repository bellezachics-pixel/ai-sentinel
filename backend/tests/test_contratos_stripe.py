"""Regresiones de consistencia de contratos Stripe (validaciones Codex).

La consistencia se ordena por IDENTIFICADOR de suscripcion, no solo por
timestamp: un evento (suscripcion, factura o reembolso) de la suscripcion
ANTERIOR nunca bloquea, reemplaza ni cancela la suscripcion VIGENTE de la
clienta. Una recontratacion no descarta trabajos de cancelacion que aun
no se confirmaron, y un reembolso NO es evidencia de cierre remoto.
"""
import asyncio
from unittest.mock import MagicMock

import pytest
import stripe as stripe_lib

from app.api.routes import billing
from app.core import billing_store


@pytest.fixture
def record(monkeypatch):
    data = {
        "status": "active",
        "stripe_customer_id": "cus_offline",
        "stripe_subscription_id": "sub_new",
        "last_canceled_subscription_id": "sub_old",
        "last_event_created": 200,
        "cancellation_pending": False,
    }
    monkeypatch.setattr(billing_store, "_cache", {"user-offline": data})
    monkeypatch.setattr(billing_store, "_save", lambda _: None)
    return data


# ============================================================
# Pertenencia por identificador (ronda 3 final)
# ============================================================

def test_cancelacion_de_suscripcion_anterior_no_bloquea_la_nueva(record):
    # La cancelacion remota del contrato viejo termina DESPUES de activar
    # el nuevo; el timestamp es legitimamente mas reciente. Aun asi solo
    # cierra el contrato viejo: el acceso vigente queda intacto.
    billing._sync_subscription_event(
        {"customer": "cus_offline", "id": "sub_old", "status": "canceled"},
        event_created=300,
        event_type="customer.subscription.deleted",
    )
    assert (record["status"], record["stripe_subscription_id"]) == ("active", "sub_new"), record


def test_nueva_contratacion_no_descarta_cancelacion_pendiente(record, monkeypatch):
    # Reembolso total con cancelacion pendiente (fallo previo de Stripe) y
    # despues contratacion legitima nueva: el alta nueva NO confirma que la
    # anterior se cancelo, asi que el trabajo pendiente se conserva.
    record.update(status="refunded", stripe_subscription_id="sub_old",
                  cancellation_pending=True)
    billing._sync_subscription_event(
        {"customer": "cus_offline", "id": "sub_new", "status": "trialing"},
        event_created=300,
        event_type="customer.subscription.updated",
    )
    assert record["stripe_subscription_id"] == "sub_new"  # acceso vigente
    canceled = []
    monkeypatch.setattr(billing.stripe.Subscription, "list",
                        lambda **kw: {"data": [{"id": "sub_old"}]})
    monkeypatch.setattr(billing.stripe.Subscription, "cancel",
                        lambda sid: canceled.append(sid))
    billing._retry_pending_cancellations()
    # Sigue existiendo una suscripcion vieja activa en Stripe: el reintento
    # cancela SOLO esa, no la nueva.
    assert canceled == ["sub_old"], {"record": record, "cancellations": canceled}


def test_factura_vieja_no_reemplaza_suscripcion_actual(record):
    # El handler de facturas ahora chequea antiguedad y pertenencia: una
    # factura fallida de la suscripcion anterior no deja morosa la vigente.
    billing._handle_webhook_event({
        "id": "evt_offline_old_invoice",
        "created": 100,
        "type": "invoice.payment_failed",
        "data": {"object": {"customer": "cus_offline", "subscription": "sub_old"}},
    })
    assert (record["status"], record["stripe_subscription_id"]) == ("active", "sub_new"), record


def test_factura_de_contrato_anterior_reciente_tampoco_aplica(record):
    # Incluso sin el argumento de antiguedad: pertenencia por identificador.
    billing._handle_webhook_event({
        "id": "evt_offline_old_invoice_recent",
        "created": 400,
        "type": "invoice.payment_failed",
        "data": {"object": {"customer": "cus_offline", "subscription": "sub_old"}},
    })
    assert (record["status"], record["stripe_subscription_id"]) == ("active", "sub_new"), record


def test_reembolso_de_cobro_anterior_no_cancela_suscripcion_nueva(record, monkeypatch):
    # El cobro pertenece a la suscripcion anterior (factura no resoluble
    # aqui): el reembolso se registra pero el acceso vigente no se toca y
    # ningun trabajo pendiente apunta a la suscripcion nueva.
    billing._record_refund_from_charge({
        "id": "ch_old", "customer": "cus_offline", "invoice": "in_old",
        "amount": 1600, "amount_refunded": 1600,
    })
    assert record["status"] == "active"  # acceso vigente intacto
    canceled = []
    monkeypatch.setattr(billing.stripe.Subscription, "list",
                        lambda **kw: {"data": [{"id": "sub_new"}]})
    monkeypatch.setattr(billing.stripe.Subscription, "cancel",
                        lambda sid: canceled.append(sid))
    billing._retry_pending_cancellations()
    assert "sub_new" not in canceled, {"record": record, "cancellations": canceled}


def test_reembolso_resuelto_de_contrato_anterior_conserva_su_pendiente(record, monkeypatch):
    # Rama productiva: la factura SI resuelve y apunta al contrato viejo.
    # Un reembolso total NO confirma el cierre remoto: el trabajo de
    # cancelacion se conserva hasta que Stripe confirme la cancelacion.
    record.update(pending_cancellation_sub_ids=["sub_old"],
                  cancellation_pending=True)
    monkeypatch.setattr(
        billing.stripe.Invoice, "retrieve",
        lambda invoice_id: {"id": invoice_id, "subscription": "sub_old"},
    )
    billing._record_refund_from_charge({
        "id": "ch_old", "customer": "cus_offline", "invoice": "in_old",
        "amount": 1600, "amount_refunded": 1600,
    })
    assert record["status"] == "active"
    assert record["stripe_subscription_id"] == "sub_new"
    assert record["pending_cancellation_sub_ids"] == ["sub_old"]
    # Cuando el reintento corre, SI se cancela el contrato viejo:
    monkeypatch.setattr(billing.stripe.Subscription, "list",
                        lambda **kw: {"data": [{"id": "sub_old", "status": "active"}]})
    canceled = []
    monkeypatch.setattr(billing.stripe.Subscription, "cancel",
                        lambda sid: canceled.append(sid))
    billing._retry_pending_cancellations()
    assert canceled == ["sub_old"], {"record": record, "cancellations": canceled}


def test_reembolso_resuelto_del_contrato_vigente_si_marca_reembolsado(record, monkeypatch):
    # Control positivo: la factura resuelve a la suscripcion VIGENTE y el
    # reembolso total si pasa la cuenta a refunded con trabajo durable.
    record.update(stripe_subscription_id="sub_new",
                  last_canceled_subscription_id=None)
    monkeypatch.setattr(
        billing.stripe.Invoice, "retrieve",
        lambda invoice_id: {"id": invoice_id, "subscription": "sub_new"},
    )
    billing._record_refund_from_charge({
        "id": "ch_new", "customer": "cus_offline", "invoice": "in_new",
        "amount": 1600, "amount_refunded": 1600,
    })
    assert record["status"] == "refunded"
    assert record["stripe_subscription_id"] is None
    assert record["last_canceled_subscription_id"] == "sub_new"
    assert record["pending_cancellation_sub_ids"] == ["sub_new"]
    assert record["cancellation_pending"] is True


# ============================================================
# Validacion Codex del commit b69fe6d (4 hallazgos)
# ============================================================

def test_admin_refund_de_cargo_historico_no_cancela_contrato_nuevo(record, monkeypatch):
    # Devolucion administrativa de un cargo de sub_old cuando la clienta
    # ya tiene sub_new vigente: se reembolsa el dinero, pero NO se cancela
    # ninguna suscripcion activa.
    monkeypatch.setattr(billing, "get_stripe_client", lambda: billing.stripe)
    monkeypatch.setattr(billing.stripe.Charge, "retrieve",
                        lambda cid: {"id": cid, "customer": "cus_offline", "invoice": "in_old"})
    monkeypatch.setattr(billing.stripe.Invoice, "retrieve",
                        lambda iid: {"id": iid, "subscription": "sub_old"})
    monkeypatch.setattr(billing.stripe.Refund, "create",
                        lambda **kw: {"id": "re_offline", "amount": 1600, "status": "succeeded"})
    canceled = []
    monkeypatch.setattr(billing.stripe.Subscription, "list",
                        lambda **kw: {"data": [{"id": "sub_new", "status": "active"}]})
    monkeypatch.setattr(billing.stripe.Subscription, "cancel",
                        lambda sid: canceled.append(sid))
    payload = billing.AdminRefundRequest(payment_id="ch_old",
                                         reason="requested_by_customer")
    result = asyncio.run(billing.admin_refund(payload, admin=MagicMock()))
    assert "sub_new" not in canceled, {"canceled": canceled}
    assert record["status"] == "active", record
    assert "warning" in result


def test_reembolso_completo_no_confirma_cancelacion_remota_pendiente(record, monkeypatch):
    # El reembolso total de un contrato con trabajo pendiente NO descarta
    # el trabajo: el contrato viejo sigue activo en Stripe y debe cerrarse.
    record.update(cancellation_pending=True,
                  pending_cancellation_sub_ids=["sub_old"])
    monkeypatch.setattr(billing.stripe.Invoice, "retrieve",
                        lambda iid: {"id": iid, "subscription": "sub_old"})
    billing._record_refund_from_charge({
        "id": "ch_old", "customer": "cus_offline", "invoice": "in_old",
        "amount": 1600, "amount_refunded": 1600,
    })
    assert record["pending_cancellation_sub_ids"] == ["sub_old"], record
    canceled = []
    monkeypatch.setattr(billing.stripe.Subscription, "list",
                        lambda **kw: {"data": [{"id": "sub_old", "status": "active"}]})
    monkeypatch.setattr(billing.stripe.Subscription, "cancel",
                        lambda sid: canceled.append(sid))
    billing._retry_pending_cancellations()
    assert canceled == ["sub_old"], {"record": record, "cancellations": canceled}


def test_retry_cancela_contrato_past_due(record, monkeypatch):
    # Un filtro "active" oculta los contratos past_due que siguen
    # cobrando: el reintento pregunta sin filtro y los cancela.
    record.update(cancellation_pending=True,
                  pending_cancellation_sub_ids=["sub_old"])
    monkeypatch.setattr(billing.stripe.Subscription, "list",
                        lambda **kw: {"data": [{"id": "sub_old", "status": "past_due"}]})
    canceled = []
    monkeypatch.setattr(billing.stripe.Subscription, "cancel",
                        lambda sid: canceled.append(sid))
    summary = billing._retry_pending_cancellations()
    assert canceled == ["sub_old"], record
    assert record["pending_cancellation_sub_ids"] == []
    assert summary["canceled"] == 1


def test_retry_descarta_contrato_con_estado_terminal_comprobado(record, monkeypatch):
    record.update(cancellation_pending=True,
                  pending_cancellation_sub_ids=["sub_old"])
    monkeypatch.setattr(billing.stripe.Subscription, "list",
                        lambda **kw: {"data": [{"id": "sub_old", "status": "canceled"}]})
    canceled = []
    monkeypatch.setattr(billing.stripe.Subscription, "cancel",
                        lambda sid: canceled.append(sid))
    billing._retry_pending_cancellations()
    assert canceled == []
    assert record["pending_cancellation_sub_ids"] == []


def test_retry_conserva_pendiente_si_la_consulta_falla(record, monkeypatch):
    record.update(cancellation_pending=True,
                  pending_cancellation_sub_ids=["sub_old"])

    def _list_falla(**kw):
        raise stripe_lib.error.StripeError("sin conexion")

    monkeypatch.setattr(billing.stripe.Subscription, "list", _list_falla)
    summary = billing._retry_pending_cancellations()
    assert record["pending_cancellation_sub_ids"] == ["sub_old"], record
    assert record["cancellation_pending"] is True
    assert summary["failures"] == 1
    assert summary["canceled"] == 0


def test_endpoint_retry_sin_pasarela_devuelve_503(record, monkeypatch):
    from fastapi import HTTPException

    from app.core import billing as billing_core

    monkeypatch.setattr(billing_core.settings, "STRIPE_SECRET_KEY", "")
    monkeypatch.setattr(billing_core, "_stripe_ready", False)
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(billing.admin_retry_cancellations(admin=MagicMock()))
    assert exc_info.value.status_code == 503


def test_endpoint_retry_inicializa_cliente_y_reporta(record, monkeypatch):
    from app.core import billing as billing_core

    record.update(cancellation_pending=True,
                  pending_cancellation_sub_ids=["sub_old"])
    monkeypatch.setattr(billing_core.settings, "STRIPE_SECRET_KEY",
                        "sk_test_placeholder")
    monkeypatch.setattr(billing_core, "_stripe_ready", False)
    monkeypatch.setattr(billing.stripe, "api_key", None)
    monkeypatch.setattr(billing.stripe.Subscription, "list",
                        lambda **kw: {"data": [{"id": "sub_old", "status": "active"}]})
    canceled = []
    monkeypatch.setattr(billing.stripe.Subscription, "cancel",
                        lambda sid: canceled.append(sid))
    result = asyncio.run(billing.admin_retry_cancellations(admin=MagicMock()))
    # El endpoint inicializo el cliente antes de recorrer:
    assert billing.stripe.api_key == "sk_test_placeholder"
    assert canceled == ["sub_old"]
    assert result["canceled"] == 1
    assert result["remaining"] == 0
    assert result["status"] == "ok"
