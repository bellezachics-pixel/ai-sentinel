"""Casos observados en el recorrido Stripe TEST desplegado en staging."""
import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.api.routes import billing
from app.core import billing_store


def test_subscription_event_reads_period_from_modern_stripe_items(monkeypatch):
    record = {"stripe_customer_id": "cus_test", "stripe_subscription_id": "sub_test",
              "status": "trialing", "last_event_created": 100}
    monkeypatch.setattr(billing_store, "_cache", {"user_test": record})
    monkeypatch.setattr(billing_store, "_save", lambda _: None)
    billing._sync_subscription_event(
        {"id": "sub_test", "customer": "cus_test", "status": "active",
         "items": {"data": [{"current_period_end": 1795327734}]}},
        event_created=200, event_type="customer.subscription.updated",
    )
    assert record["current_period_end"] == "2026-11-22T06:08:54+00:00"
    assert record["status"] == "active"


def test_paid_invoice_uses_service_period_not_invoice_creation_window(monkeypatch):
    record = {"stripe_customer_id": "cus_test", "stripe_subscription_id": "sub_test",
              "status": "active", "current_period_end": "2026-11-22T06:08:54+00:00"}
    monkeypatch.setattr(billing_store, "_cache", {"user_test": record})
    monkeypatch.setattr(billing_store, "_save", lambda _: None)
    billing._handle_webhook_event({"type": "invoice.payment_succeeded", "created": 200,
        "data": {"object": {"customer": "cus_test", "subscription": "sub_test",
                 "amount_paid": 1600, "period_end": 1792649334,
                 "lines": {"data": [{"period": {"end": 1795327734}}]}}}})
    assert record["current_period_end"] == "2026-11-22T06:08:54+00:00"
    assert record["last_payment_amount"] == 1600


def test_legacy_period_fields_still_supported():
    assert billing._subscription_period_end({"current_period_end": 1795327734}) == 1795327734
    assert billing._invoice_period_end({"period_end": 1795327734}) == 1795327734


def test_history_distinguishes_refunded_charge_from_successful_charge(monkeypatch):
    client = MagicMock()
    client.Charge.list.return_value = {"data": [
        {"id": "ch_refunded", "amount": 1600, "currency": "usd", "status": "succeeded",
         "refunded": True, "created": 1792649334},
        {"id": "ch_paid", "amount": 1600, "currency": "usd", "status": "succeeded",
         "refunded": False, "created": 1792649234},
    ]}
    monkeypatch.setattr(billing, "get_stripe_client", lambda: client)
    monkeypatch.setattr(billing_store, "get_record", lambda _: {"stripe_customer_id": "cus_test"})
    result = asyncio.run(billing.list_payments(SimpleNamespace(id="user_test")))
    assert [(p["id"], p["status"]) for p in result["payments"]] == [
        ("ch_refunded", "refunded"), ("ch_paid", "succeeded")]
