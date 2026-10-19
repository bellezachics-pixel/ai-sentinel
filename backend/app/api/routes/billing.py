"""
Rutas de Billing (Stripe TEST) - Guardia Flow

Contrato del frontend (ver frontend/src/lib/billing.ts):
- POST /api/v1/billing/checkout  -> {"checkout_url": str} | 409 | 503
- POST /api/v1/billing/portal    -> {"portal_url": str} | 404
- GET  /api/v1/billing/status    -> {has_access, status, trial_end,
                                     current_period_end, cancel_at_period_end,
                                     plan_price}
- GET  /api/v1/billing/payments  -> {"payments": [...]} | 401 | 503
- POST /api/v1/billing/webhook   -> {"received": true} | 400 (sin JWT;
                                     verifica Stripe-Signature)
- POST /api/v1/billing/admin/refund -> {"refund_id", "amount", "status"}
                                     | 400 | 403 | 502 | 503 (JWT + admin)

SOLO modo TEST. Jamas configurar claves live de Stripe.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

import stripe

from app.core import billing_store
from app.core.auth import UserInDB, require_admin, require_auth
from app.core.billing import (
    PLAN_PRICE_LABEL,
    get_stripe_client,
    has_access,
    stripe_configured,
    trial_end_for,
)
from app.core.config import settings
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/billing", tags=["Billing"])

PRODUCT_NAME = "Guardia Flow Pro"
PRODUCT_AMOUNT_CENTS = 1600  # US$16.00/mes
TRIAL_PERIOD_DAYS = 3

# Eventos de suscripcion que sincronizan el store local.
SUBSCRIPTION_EVENTS = {
    "customer.subscription.updated",
    "customer.subscription.deleted",
}

# Eventos de reembolso: charge.refunded trae el charge completo;
# charge.refund.updated trae el refund (hay que recuperar el charge).
REFUND_EVENTS = {
    "charge.refunded",
    "charge.refund.updated",
}


def _unix_to_iso(value) -> Optional[str]:
    """Convierte timestamp unix de Stripe a ISO 8601 (UTC)."""
    if value in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def _frontend_billing_url(path: str) -> str:
    return f"{settings.FRONTEND_URL.rstrip('/')}/billing/{path}"


def _resolve_price_id(client) -> str:
    """
    Devuelve STRIPE_PRICE_ID o busca/crea el producto "Guardia Flow Pro"
    (USD 16/mes recurrente) en el dashboard de Stripe TEST. Los IDs creados
    se registran en el log para pegarlos en el .env.
    """
    if settings.STRIPE_PRICE_ID:
        return settings.STRIPE_PRICE_ID

    products = client.Product.list(active=True, limit=100)
    product = next(
        (p for p in products.get("data", []) if p.get("name") == PRODUCT_NAME),
        None,
    )
    if product is None:
        product = client.Product.create(name=PRODUCT_NAME)
        logger.warning(
            "STRIPE_PRICE_ID vacio: se creo el producto %s (%s). "
            "Copia este ID en STRIPE_PRICE_ID del .env.",
            PRODUCT_NAME, product["id"],
        )

    prices = client.Price.list(product=product["id"], active=True, limit=100)
    price = next(
        (
            p for p in prices.get("data", [])
            if p.get("recurring", {}).get("interval") == "month"
            and p.get("currency") == "usd"
            and p.get("unit_amount") == PRODUCT_AMOUNT_CENTS
        ),
        None,
    )
    if price is None:
        price = client.Price.create(
            product=product["id"],
            unit_amount=PRODUCT_AMOUNT_CENTS,
            currency="usd",
            recurring={"interval": "month"},
        )
        logger.warning(
            "STRIPE_PRICE_ID vacio: se creo el price %s (%s, %s). "
            "Copia este ID en STRIPE_PRICE_ID del .env.",
            price["id"], PRODUCT_NAME, PLAN_PRICE_LABEL,
        )
    return price["id"]


def _get_or_create_customer(client, user: UserInDB, record: dict) -> str:
    existing = record.get("stripe_customer_id")
    if existing:
        return existing
    customers = client.Customer.list(email=user.email, limit=1)
    customer = (
        customers["data"][0]
        if customers.get("data")
        else None
    )
    if customer is None:
        customer = client.Customer.create(
            email=user.email,
            metadata={"user_id": user.id},
        )
    billing_store.upsert_record(
        user.id, stripe_customer_id=customer["id"]
    )
    return customer["id"]


# ============================================================
# POST /api/v1/billing/checkout
# ============================================================
@router.post("/checkout")
async def create_checkout_session(user: UserInDB = Depends(require_auth)):
    """Crear sesion de Stripe Checkout (suscripcion US$16/mes, 3 dias de trial)."""
    client = get_stripe_client()
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="pasarela_no_configurada",
        )

    record = billing_store.get_record(user.id)
    if record.get("status") in billing_store.ACCESS_GRANTING_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="ya_existe_suscripcion_activa",
        )

    try:
        customer_id = _get_or_create_customer(client, user, record)
        price_id = _resolve_price_id(client)
        session = client.checkout.Session.create(
            mode="subscription",
            customer=customer_id,
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=_frontend_billing_url(
                "success?session_id={CHECKOUT_SESSION_ID}"
            ),
            cancel_url=_frontend_billing_url("cancel"),
            metadata={"user_id": user.id},
            subscription_data={"trial_period_days": TRIAL_PERIOD_DAYS},
        )
    except HTTPException:
        raise
    except stripe.error.StripeError as exc:
        logger.error("Stripe checkout error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="error_pasarela_pago",
        )

    return {"checkout_url": session["url"]}


# ============================================================
# POST /api/v1/billing/portal
# ============================================================
@router.post("/portal")
async def create_portal_session(user: UserInDB = Depends(require_auth)):
    """Crear sesion del portal de facturacion de Stripe (gestionar/cancelar)."""
    client = get_stripe_client()
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="pasarela_no_configurada",
        )

    record = billing_store.get_record(user.id)
    customer_id = record.get("stripe_customer_id")
    if not customer_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="cliente_stripe_no_encontrado",
        )

    try:
        session = client.billing_portal.Session.create(
            customer=customer_id,
            return_url=settings.FRONTEND_URL.rstrip("/"),
        )
    except stripe.error.StripeError as exc:
        logger.error("Stripe portal error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="error_pasarela_pago",
        )

    return {"portal_url": session["url"]}


# ============================================================
# GET /api/v1/billing/status
# ============================================================
@router.get("/status")
async def get_billing_status(user: UserInDB = Depends(require_auth)):
    """Estado de acceso del usuario: suscripcion Stripe + trial local."""
    record = billing_store.get_record(user.id)
    subscription_status = record.get("status") or "none"

    # trial_end: prioriza el dato de Stripe; si no, el trial local.
    trial_end = record.get("trial_end")
    if not trial_end:
        local_end = trial_end_for(user)
        trial_end = local_end.isoformat() if local_end else None

    # Si no hay suscripcion en Stripe pero el trial local sigue vivo,
    # reportar "trialing" para que la UI muestre el contador de dias.
    if subscription_status == "none" and trial_end:
        from app.core.billing import trial_active

        if trial_active(user):
            subscription_status = "trialing"

    return {
        "has_access": has_access(user, record),
        "status": subscription_status,
        "trial_end": trial_end,
        "current_period_end": record.get("current_period_end"),
        "cancel_at_period_end": bool(record.get("cancel_at_period_end", False)),
        "plan_price": PLAN_PRICE_LABEL,
    }


# ============================================================
# POST /api/v1/billing/webhook  (SIN JWT; verifica Stripe-Signature)
# ============================================================
def _record_refund_from_charge(charge: dict):
    """
    Persiste un reembolso asociado a un charge en el registro local del
    usuario (localizado por stripe_customer_id). Si el charge fue
    reembolsado EN SU TOTALIDAD, el estado pasa a "refunded" y se limpia
    el id de suscripcion: has_access devuelve False de ahora en adelante.
    """
    customer_id = charge.get("customer")
    user_id, _record = billing_store.get_record_by_customer(customer_id)
    if user_id is None:
        logger.warning(
            "Webhook: charge %s sin cliente local conocido (%s)",
            charge.get("id"), customer_id,
        )
        return

    try:
        amount = int(charge.get("amount") or 0)
        refunded = int(charge.get("amount_refunded") or 0)
    except (TypeError, ValueError):
        return

    fields = {
        "stripe_customer_id": customer_id,
        "last_refund_at": datetime.now(timezone.utc).isoformat(),
        "last_refund_amount": refunded,
    }
    if amount > 0 and refunded >= amount:
        fields["status"] = "refunded"
        fields["stripe_subscription_id"] = None
    billing_store.upsert_record(user_id, **fields)


def _sync_subscription_event(subscription: dict):
    """Persiste el estado de una suscripcion en el store local."""
    customer_id = subscription.get("customer")
    user_id, record = billing_store.get_record_by_customer(customer_id)
    if user_id is None:
        # Fallback: el checkout.session.completed vincula despues; sin
        # customer conocido no hay a quien acreditar el evento.
        logger.warning(
            "Webhook: suscripcion %s sin cliente local conocido (%s)",
            subscription.get("id"), customer_id,
        )
        return
    billing_store.upsert_record(
        user_id,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription.get("id"),
        status=subscription.get("status") or "none",
        trial_end=_unix_to_iso(subscription.get("trial_end")),
        current_period_end=_unix_to_iso(subscription.get("current_period_end")),
        cancel_at_period_end=bool(subscription.get("cancel_at_period_end", False)),
    )


def _handle_webhook_event(event: dict):
    event_type = event.get("type")
    data = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        user_id = (data.get("metadata") or {}).get("user_id")
        if not user_id:
            logger.warning("Webhook: checkout.session.completed sin metadata.user_id")
            return
        # No resucitar estados protegidos: una reentrega antigua de este
        # evento NO puede revertir una cancelacion/reembolso ni rebajar
        # una suscripcion activa o morosa a "trialing".
        existing = billing_store.get_record(user_id)
        current_status = (existing.get("status") or "").lower()
        if current_status in billing_store.CHECKOUT_PROTECTED_STATUSES:
            logger.info(
                "Webhook: checkout.session.completed ignorado para %s "
                "(estado actual protegido: %s)",
                user_id, current_status,
            )
            return
        billing_store.upsert_record(
            user_id,
            stripe_customer_id=data.get("customer"),
            stripe_subscription_id=data.get("subscription"),
            status="trialing",
        )
        # Si la suscripcion ya existe en el evento de suscripcion, el
        # evento customer.subscription.* la sincronizara con detalle.
    elif event_type in SUBSCRIPTION_EVENTS:
        _sync_subscription_event(data)
    elif event_type == "invoice.payment_failed":
        customer_id = data.get("customer")
        user_id, _record = billing_store.get_record_by_customer(customer_id)
        if user_id:
            billing_store.upsert_record(
                user_id,
                stripe_customer_id=customer_id,
                stripe_subscription_id=data.get("subscription"),
                status="past_due",
            )
    elif event_type == "invoice.payment_succeeded":
        customer_id = data.get("customer")
        user_id, _record = billing_store.get_record_by_customer(customer_id)
        if user_id:
            billing_store.upsert_record(
                user_id,
                stripe_customer_id=customer_id,
                stripe_subscription_id=data.get("subscription"),
                last_payment_at=datetime.now(timezone.utc).isoformat(),
                last_payment_amount=data.get("amount_paid"),
                current_period_end=_unix_to_iso(data.get("period_end")),
            )
    elif event_type == "charge.refunded":
        _record_refund_from_charge(data)
    elif event_type == "charge.refund.updated":
        # El objeto del evento es el Refund: recuperamos el charge para
        # evaluar si ya fue reembolsado en su totalidad.
        charge_id = data.get("charge")
        client = get_stripe_client()
        if not charge_id or client is None:
            return
        try:
            charge = client.Charge.retrieve(charge_id)
        except stripe.error.StripeError as exc:
            logger.warning(
                "Webhook: no se pudo recuperar el charge %s (%s)",
                charge_id, exc,
            )
            return
        _record_refund_from_charge(charge)
    else:
        logger.info("Webhook: evento no manejado (%s)", event_type)


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """
    Recibe eventos de Stripe. Requiere el header Stripe-Signature y el
    cuerpo RAW (no parseado) para la verificacion de firma.
    """
    if not settings.STRIPE_WEBHOOK_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="pasarela_no_configurada",
        )

    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload, signature, settings.STRIPE_WEBHOOK_SECRET
        )
    except stripe.error.SignatureVerificationError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="firma_webhook_invalida",
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payload_webhook_invalido",
        )

    # Deduplicacion: Stripe reentrega eventos (timeouts, reintentos, o
    # configuraciones con entrega duplicada). Un evento ya procesado se
    # confirma de nuevo sin reejecutarlo (idempotencia real).
    event_id = event.get("id")
    if event_id and billing_store.has_event(event_id):
        return {"received": True, "duplicate": True}

    try:
        _handle_webhook_event(event)
    except Exception:
        logger.exception("Webhook: error al procesar el evento %s", event_id)
        # No confirmar recepcion si el procesamiento fallo: Stripe reintenta
        # la entrega y el estado no se pierde en silencio.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="error_procesando_evento",
        )

    if event_id:
        billing_store.record_event(event_id)

    return {"received": True}


# ============================================================
# GET /api/v1/billing/payments  (JWT)
# ============================================================
@router.get("/payments")
async def list_payments(user: UserInDB = Depends(require_auth)):
    """
    Historial de cobros del cliente de Stripe (mas recientes primero,
    maximo 20). Sin customer de Stripe devuelve lista vacia.
    """
    client = get_stripe_client()
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="pasarela_no_configurada",
        )

    record = billing_store.get_record(user.id)
    customer_id = record.get("stripe_customer_id")
    if not customer_id:
        return {"payments": []}

    try:
        charges = client.Charge.list(customer=customer_id, limit=20)
    except stripe.error.StripeError as exc:
        logger.error("Stripe payments error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="error_pasarela_pago",
        )

    payments = [
        {
            "id": charge.get("id"),
            "amount": charge.get("amount"),
            "currency": charge.get("currency"),
            "status": charge.get("status"),
            "description": charge.get("description"),
            "date": _unix_to_iso(charge.get("created")),
            "receipt_url": charge.get("receipt_url"),
        }
        for charge in (charges.get("data") or [])[:20]
    ]
    payments.sort(key=lambda p: p["date"] or "", reverse=True)
    return {"payments": payments}


# ============================================================
# POST /api/v1/billing/admin/refund  (JWT + admin)
# ============================================================
REFUND_REASONS = {"duplicate", "fraudulent", "requested_by_customer"}


class AdminRefundRequest(BaseModel):
    payment_id: str
    reason: str = "requested_by_customer"
    amount: Optional[int] = None  # centavos; None = reembolso total


def _charge_from_payment_intent(client, payment_intent_id: str):
    """Localiza el charge asociado a un PaymentIntent -> (charge_id, customer)."""
    charges = client.Charge.list(payment_intent=payment_intent_id, limit=1)
    data = charges.get("data") or []
    if not data:
        return None, None
    return data[0].get("id"), data[0].get("customer")


def _resolve_payment_to_charge(client, payment_id: str):
    """
    Acepta un id de Checkout Session (cs_...), PaymentIntent (pi_...) o
    Charge (ch_...) y devuelve (charge_id, stripe_customer_id).
    """
    payment_id = (payment_id or "").strip()
    if payment_id.startswith("cs_"):
        session = client.checkout.Session.retrieve(payment_id)
        payment_intent = session.get("payment_intent")
        if not payment_intent:
            return None, None
        return _charge_from_payment_intent(client, payment_intent)
    if payment_id.startswith("pi_"):
        return _charge_from_payment_intent(client, payment_id)
    if payment_id.startswith("ch_"):
        charge = client.Charge.retrieve(payment_id)
        return charge.get("id"), charge.get("customer")
    return None, None


@router.post("/admin/refund")
async def admin_refund(
    payload: AdminRefundRequest,
    admin: UserInDB = Depends(require_admin),
):
    """
    Reembolso administrativo (modo TEST). Crea el refund en Stripe y lo
    registra en el store local del usuario afectado.
    """
    if payload.reason not in REFUND_REASONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="motivo_reembolso_invalido",
        )

    client = get_stripe_client()
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="pasarela_no_configurada",
        )

    try:
        charge_id, customer_id = _resolve_payment_to_charge(
            client, payload.payment_id
        )
    except stripe.error.StripeError as exc:
        logger.error("Stripe refund resolve error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="error_pasarela_pago",
        )
    if not charge_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payment_id_invalido",
        )

    refund_kwargs = {"charge": charge_id, "reason": payload.reason}
    if payload.amount is not None:
        refund_kwargs["amount"] = payload.amount

    try:
        refund = stripe.Refund.create(**refund_kwargs)
    except stripe.error.StripeError as exc:
        logger.error("Stripe refund error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="error_pasarela_pago",
        )

    # Registro local del reembolso (usuario afectado, via su customer).
    user_id, _record = billing_store.get_record_by_customer(customer_id)
    if user_id:
        billing_store.upsert_record(
            user_id,
            stripe_customer_id=customer_id,
            last_refund_at=datetime.now(timezone.utc).isoformat(),
            last_refund_amount=refund.get("amount"),
            last_refund_id=refund.get("id"),
        )

    return {
        "refund_id": refund.get("id"),
        "amount": refund.get("amount"),
        "status": refund.get("status"),
    }
