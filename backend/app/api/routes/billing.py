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
    ACCESS_BLOCKING_STATUSES,
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
    usuario (localizado por stripe_customer_id).

    Pertenencia por contrato: se resuelve cargo -> factura -> suscripcion.
    El reembolso (tardio o administrativo) de un cargo de una suscripcion
    ANTERIOR no toca el acceso vigente: solo se registra, y si ese contrato
    estaba pendiente de cancelacion, un reembolso total lo confirma.

    Si el charge fue reembolsado EN SU TOTALIDAD y pertenece al contrato
    vigente, el estado pasa a "refunded" y queda un trabajo de cancelacion
    durable por identificador: has_access devuelve False y la suscripcion
    remota se cierra en el siguiente reintento.
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

    base_fields = {
        "stripe_customer_id": customer_id,
        "last_refund_at": datetime.now(timezone.utc).isoformat(),
        "last_refund_amount": refunded,
    }

    invoice_id = charge.get("invoice")
    if invoice_id:
        sub_from_charge: Optional[str] = None
        resolved = False
        try:
            invoice = stripe.Invoice.retrieve(invoice_id)
            sub_from_charge = (invoice or {}).get("subscription") or None
            resolved = True
        except Exception as exc:
            logger.warning(
                "Webhook: no se pudo resolver la factura %s del cargo %s (%s)",
                invoice_id, charge.get("id"), exc,
            )
        if not resolved:
            # Sin evidencia del contrato NO se toca el acceso vigente:
            # mejor un reembolso registrado sin cierre automatico que
            # cerrar por error el contrato nuevo de la clienta.
            billing_store.upsert_record(user_id, **base_fields)
            return
        current_sub = (_record or {}).get("stripe_subscription_id")
        if sub_from_charge and current_sub and sub_from_charge != current_sub:
            # Reembolso de un contrato anterior: el acceso vigente queda
            # intacto; si ese contrato tenia un pendiente de cancelacion,
            # el reembolso total lo confirma.
            fields = dict(base_fields)
            pending_ids = [
                s for s in ((_record or {}).get("pending_cancellation_sub_ids") or []) if s
            ]
            if (
                amount > 0
                and refunded >= amount
                and sub_from_charge in pending_ids
            ):
                fields["pending_cancellation_sub_ids"] = [
                    s for s in pending_ids if s != sub_from_charge
                ]
                fields["cancellation_pending"] = (
                    len(fields["pending_cancellation_sub_ids"]) > 0
                )
            billing_store.upsert_record(user_id, **fields)
            logger.info(
                "Webhook: reembolso de contrato anterior %s para %s; "
                "acceso vigente %s intacto",
                sub_from_charge, user_id, current_sub,
            )
            return
        # Factura sin suscripcion (pago unico): se trata como del registro,
        # comportamiento historico.

    if amount > 0 and refunded >= amount:
        fields = dict(base_fields)
        fields["status"] = "refunded"
        previous_sub = (_record or {}).get("stripe_subscription_id")
        if previous_sub:
            # Se pierde el vinculo al borrar el id: memorizarlo para que una
            # futura contratacion nueva aplique y una reentrega tardia de la
            # suscripcion reembolsada no se disfrace de contratacion nueva.
            fields["last_canceled_subscription_id"] = previous_sub
            pending_ids = [
                s for s in ((_record or {}).get("pending_cancellation_sub_ids") or []) if s
            ]
            if previous_sub not in pending_ids:
                pending_ids.append(previous_sub)
            fields["pending_cancellation_sub_ids"] = pending_ids
        fields["stripe_subscription_id"] = None
        # La suscripcion remota pudo originarse fuera de nuestro admin
        # (reembolso desde el dashboard de Stripe): si sigue activa, sigue
        # cobrando. Trabajo durable por identificador para que
        # _retry_pending_cancellations la cierre (admin/refund o el
        # endpoint admin de reintentos).
        fields["cancellation_pending"] = True
        billing_store.upsert_record(user_id, **fields)
    else:
        billing_store.upsert_record(user_id, **base_fields)


def _is_stale_event(record: dict | None, event_created: int | None) -> bool:
    """True si el evento de Stripe es MAS ANTIGUO que el ultimo aplicado.

    Stripe entrega los eventos en orden pero puede REENTREGAR eventos
    antiguos (reintentos, reproducciones). Sin este chequeo, un
    customer.subscription.updated viejo con status "active" podria
    restaurar el acceso despues de una cancelacion o reembolso.
    """
    if not record or not event_created:
        return False
    last = record.get("last_event_created")
    if last is None:
        return False
    try:
        return int(event_created) < int(last)
    except (TypeError, ValueError):
        return False


def _sync_subscription_event(subscription: dict, event_created: int | None = None, event_type: str | None = None):
    """Persiste el estado de una suscripcion en el store local.

    Protecciones de consistencia:
    - Pertenencia por identificador: un evento cuyo id NO es la suscripcion
      vigente pertenece al historial de OTRO contrato y nunca reemplaza el
      estado que otorga acceso (ni lo bloquea).
    - Nunca rebajar un estado terminal (refunded/canceled) a uno activo:
      un evento antiguo no puede resucitar el acceso.
    - Nunca aceptar un evento con timestamp menor al ultimo aplicado.
    - Recontratar no confirma cancelaciones pendientes de la suscripcion
      anterior: el trabajo se transfiere a la lista durable por identificador.
    """
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

    new_status = (subscription.get("status") or "none").lower()
    current_status = ((record or {}).get("status") or "").lower()
    new_sub_id = subscription.get("id")
    saved_sub_id = (record or {}).get("stripe_subscription_id")
    last_canceled_id = (record or {}).get("last_canceled_subscription_id")
    pending_ids = [
        s for s in ((record or {}).get("pending_cancellation_sub_ids") or []) if s
    ]

    # --- Pertenencia por identificador de contrato ---
    if new_sub_id and saved_sub_id and new_sub_id != saved_sub_id:
        if new_sub_id == last_canceled_id or new_sub_id in pending_ids:
            # Evento de un contrato ya cerrado o pendiente de cierre: solo
            # toca el HISTORIAL de ese contrato, jamas el acceso vigente.
            if (
                event_type == "customer.subscription.deleted"
                or new_status in ("canceled", "incomplete_expired")
            ):
                # Stripe confirma el cierre de ese contrato: resolver solo
                # SU pendiente, sin tocar el estado del acceso actual.
                remaining = [s for s in pending_ids if s != new_sub_id]
                if remaining != pending_ids:
                    billing_store.upsert_record(
                        user_id,
                        pending_cancellation_sub_ids=remaining,
                        cancellation_pending=len(remaining) > 0,
                    )
            else:
                logger.info(
                    "Webhook: evento de contrato anterior %s ignorado para %s "
                    "(vigente %s)", new_sub_id, user_id, saved_sub_id,
                )
            return
        if new_status in ACCESS_BLOCKING_STATUSES:
            # Estado terminal de un contrato desconocido: sin evidencia de
            # que sea el vigente, no se toca el acceso actual.
            logger.info(
                "Webhook: %s de contrato desconocido %s no se aplica a %s",
                event_type, new_sub_id, user_id,
            )
            return
        # id desconocido con estado vivo: contratacion nueva (se aplica abajo).

    # Una suscripcion con ID distinto al guardado (y distinto a la ultima
    # cancelada/reembolsada) es una CONTRATACION NUEVA legitima (la clienta
    # cancelo y volvio a contratar): debe reconciliar el estado y otorgar
    # acceso, no quedar bloqueada por el estado terminal de la suscripcion
    # anterior. El id cancelado se conserva precisamente para que una
    # REENTREGA TARDIA de la suscripcion vieja no se disfrace de contratacion
    # nueva cuando el store ya no guarda el id (reembolso total).
    is_new_subscription = bool(
        new_sub_id
        and new_sub_id != saved_sub_id
        and new_sub_id != last_canceled_id
    )

    if _is_stale_event(record, event_created):
        logger.info(
            "Webhook: %s ignorado para %s (evento antiguo: %s < %s)",
            event_type, user_id, event_created,
            (record or {}).get("last_event_created"),
        )
        return

    if (
        not is_new_subscription
        and current_status in ACCESS_BLOCKING_STATUSES
        and new_status not in ACCESS_BLOCKING_STATUSES
    ):
        logger.info(
            "Webhook: %s no reactiva acceso de %s (estado terminal %s -> %s)",
            event_type, user_id, current_status, new_status,
        )
        return

    fields = {
        "stripe_customer_id": customer_id,
        "status": subscription.get("status") or "none",
        "trial_end": _unix_to_iso(subscription.get("trial_end")),
        "current_period_end": _unix_to_iso(subscription.get("current_period_end")),
        "cancel_at_period_end": bool(subscription.get("cancel_at_period_end", False)),
        "last_event_created": event_created,
    }
    if is_new_subscription:
        # Recontratacion: el alta nueva NO demuestra que la suscripcion
        # anterior se cancelo. Transferir su pendiente (si existe) a la
        # lista durable por identificador, sin descartarlo.
        if (
            (record or {}).get("cancellation_pending")
            and saved_sub_id
            and saved_sub_id not in pending_ids
        ):
            pending_ids = pending_ids + [saved_sub_id]
        fields["pending_cancellation_sub_ids"] = pending_ids
        fields["cancellation_pending"] = len(pending_ids) > 0
    elif (
        new_sub_id
        and new_status in ("canceled", "incomplete_expired")
        and new_sub_id in pending_ids
    ):
        # El contrato vigente confirma SU cierre: resolver solo su pendiente.
        pending_ids = [s for s in pending_ids if s != new_sub_id]
        fields["pending_cancellation_sub_ids"] = pending_ids
        fields["cancellation_pending"] = len(pending_ids) > 0
    if new_sub_id:
        # Solo escribir el id cuando el evento lo trae: un evento sin id no
        # debe borrar el vinculo de suscripcion que ya tenia el registro.
        fields["stripe_subscription_id"] = new_sub_id
        if new_status in ACCESS_BLOCKING_STATUSES:
            # Estado terminal: memorizar el id cancelado/reembolsado para que
            # una contratacion futura aplique y una reentrega tardia de ESTA
            # suscripcion no se disfrace de contratacion nueva.
            fields["last_canceled_subscription_id"] = new_sub_id
    billing_store.upsert_record(user_id, **fields)


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
        _sync_subscription_event(data, event_created=event.get("created"), event_type=event_type)
    elif event_type == "invoice.payment_failed":
        customer_id = data.get("customer")
        user_id, record = billing_store.get_record_by_customer(customer_id)
        if user_id:
            # Antiguedad: una factura vieja no reemplaza el estado actual.
            if _is_stale_event(record, event.get("created")):
                logger.info(
                    "Webhook: invoice.payment_failed antiguo ignorado para %s",
                    user_id,
                )
                return
            # Pertenencia: una factura de la suscripcion ANTERIOR no debe
            # dejar morosa (ni pisar el id de) la suscripcion vigente.
            inv_sub = data.get("subscription")
            current_sub = (record or {}).get("stripe_subscription_id")
            if inv_sub and current_sub and inv_sub != current_sub:
                logger.info(
                    "Webhook: factura de contrato anterior %s ignorada para %s "
                    "(vigente %s)", inv_sub, user_id, current_sub,
                )
                return
            # No rebajar un estado terminal a "past_due": reactivaria el
            # acceso de una cuenta reembolsada/cancelada.
            current = ((record or {}).get("status") or "").lower()
            if current in ACCESS_BLOCKING_STATUSES:
                logger.info(
                    "Webhook: invoice.payment_failed ignorado para %s "
                    "(estado terminal %s)", user_id, current,
                )
                return
            fields = {
                "stripe_customer_id": customer_id,
                "status": "past_due",
            }
            if inv_sub:
                fields["stripe_subscription_id"] = inv_sub
            billing_store.upsert_record(user_id, **fields)
    elif event_type == "invoice.payment_succeeded":
        customer_id = data.get("customer")
        user_id, record = billing_store.get_record_by_customer(customer_id)
        if user_id:
            # Pertenencia: el pago de una factura del contrato anterior no
            # actualiza el periodo ni el id de la suscripcion vigente.
            inv_sub = data.get("subscription")
            current_sub = (record or {}).get("stripe_subscription_id")
            if inv_sub and current_sub and inv_sub != current_sub:
                logger.info(
                    "Webhook: pago de contrato anterior %s ignorado para %s "
                    "(vigente %s)", inv_sub, user_id, current_sub,
                )
                return
            fields = {
                "stripe_customer_id": customer_id,
                "last_payment_at": datetime.now(timezone.utc).isoformat(),
                "last_payment_amount": data.get("amount_paid"),
                "current_period_end": _unix_to_iso(data.get("period_end")),
            }
            if inv_sub:
                fields["stripe_subscription_id"] = inv_sub
            billing_store.upsert_record(user_id, **fields)
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


def _retry_pending_cancellations() -> None:
    """Reintenta las cancelaciones de suscripcion pendientes.

    Dos modalidades:
    - Lista durable `pending_cancellation_sub_ids`: cancela SOLO esos
      contratos, identificador por identificador, y nunca la suscripcion
      que otorga el acceso vigente del registro.
    - Legado (`cancellation_pending=True` sin lista): conserva el
      comportamiento original (cancela las suscripciones activas del
      customer), para registros existentes previos a este campo.

    Idempotente y SEGURO de repetir: jamas crea reembolsos. Vias de
    ejecucion: al entrar a /admin/refund y el endpoint
    /admin/billing/retry-cancellations.
    """
    for user_id, record in billing_store.all_records().items():
        pending_ids = [
            s for s in (record.get("pending_cancellation_sub_ids") or []) if s
        ]
        if pending_ids:
            _retry_pending_ids(user_id, record, pending_ids)
        elif record.get("cancellation_pending"):
            _retry_pending_legacy(user_id, record)


def _retry_pending_ids(user_id: str, record: dict, pending_ids: list) -> None:
    """Cancela en Stripe los contratos pendientes, uno por uno."""
    customer_id = record.get("stripe_customer_id")
    if not customer_id:
        billing_store.upsert_record(
            user_id,
            pending_cancellation_sub_ids=[],
            cancellation_pending=False,
        )
        return
    try:
        active_subs = stripe.Subscription.list(
            customer=customer_id, status="active", limit=100
        ).get("data", [])
    except stripe.error.StripeError as exc:
        logger.error("Reintento de cancelacion fallo para %s: %s", user_id, exc)
        return
    active_ids = {s.get("id") for s in active_subs if s.get("id")}
    current_sub = record.get("stripe_subscription_id")
    current_status = (record.get("status") or "").lower()
    canceled_now: list[str] = []
    skipped_vigente: list[str] = []
    for sub_id in pending_ids:
        if sub_id not in active_ids:
            continue  # ya no activa en Stripe: cierre confirmado por ausencia
        if (
            sub_id == current_sub
            and current_status in billing_store.ACCESS_GRANTING_STATUSES
        ):
            # Es la suscripcion que otorga acceso ahora: el pendiente
            # apuntaba por error al contrato nuevo; no cancelarla.
            skipped_vigente.append(sub_id)
            logger.warning(
                "Cancelacion pendiente %s coincide con la suscripcion vigente "
                "de %s: se omite (revisar manualmente)", sub_id, user_id,
            )
            continue
        try:
            stripe.Subscription.cancel(sub_id)
            canceled_now.append(sub_id)
        except stripe.error.StripeError as exc:
            logger.error(
                "Cancelacion pendiente fallo para %s (%s): %s",
                user_id, sub_id, exc,
            )
    remaining = [
        s for s in pending_ids
        if s in active_ids and s not in canceled_now and s not in skipped_vigente
    ]
    fields: dict = {
        "pending_cancellation_sub_ids": remaining,
        "cancellation_pending": len(remaining) > 0,
    }
    if (
        current_sub
        and current_sub in canceled_now
        and current_status not in billing_store.ACCESS_GRANTING_STATUSES
    ):
        # Se cerro el contrato que el registro tenia vinculado y sin acceso:
        # limpiar el vinculo y memorizarlo como ultimo cancelado.
        fields["stripe_subscription_id"] = None
        fields["last_canceled_subscription_id"] = current_sub
    billing_store.upsert_record(user_id, **fields)
    if canceled_now:
        logger.info(
            "Reintento de cancelacion resuelto para %s (contratos: %s)",
            user_id, ", ".join(canceled_now),
        )


def _retry_pending_legacy(user_id: str, record: dict) -> None:
    """Modalidad de compatibilidad para registros previos a la lista por id."""
    customer_id = record.get("stripe_customer_id")
    if not customer_id:
        billing_store.upsert_record(
            user_id,
            pending_cancellation_sub_ids=[],
            cancellation_pending=False,
        )
        return
    try:
        active_subs = stripe.Subscription.list(
            customer=customer_id, status="active", limit=10
        ).get("data", [])
        for sub in active_subs:
            stripe.Subscription.cancel(sub["id"])
        fields = {
            "stripe_subscription_id": None,
            "cancellation_pending": False,
            "pending_cancellation_sub_ids": [],
        }
        if active_subs:
            # Memorizar la cancelada: una contratacion futura debe
            # aplicar, y una reentrega tardia de esta suscripcion no.
            fields["last_canceled_subscription_id"] = active_subs[-1]["id"]
        billing_store.upsert_record(user_id, **fields)
        logger.info(
            "Reintento de cancelacion resuelto para %s (%d suscripciones)",
            user_id, len(active_subs),
        )
    except stripe.error.StripeError as exc:
        logger.error(
            "Reintento de cancelacion fallo para %s: %s", user_id, exc
        )


@router.post("/admin/billing/retry-cancellations")
async def admin_retry_cancellations(admin: UserInDB = Depends(require_admin)):
    """Ejecuta el reintento de cancelaciones pendientes SIN crear reembolsos.

    Via independiente para trabajos originados por webhooks remotos
    (reembolso desde el dashboard de Stripe) que de otro modo solo se
    procesarian al entrar a /admin/refund.
    """
    _retry_pending_cancellations()
    return {"status": "ok"}


@router.post("/admin/refund")
async def admin_refund(
    payload: AdminRefundRequest,
    admin: UserInDB = Depends(require_admin),
):
    """
    Reembolso administrativo (modo TEST). Crea el refund en Stripe y lo
    registra en el store local del usuario afectado.
    """
    # Antes de procesar, resolver cancelaciones que quedaron pendientes
    # por fallos transitorios anteriores (idempotente).
    _retry_pending_cancellations()
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

    # Un reembolso TOTAL debe cancelar la suscripcion activa del cliente:
    # sin esto la suscripcion sigue viva en Stripe y vuelve a cobrar en el
    # siguiente ciclo aunque el dinero ya haya sido devuelto.
    canceled_subscriptions: list[str] = []
    cancellation_error: str | None = None
    if payload.amount is None and customer_id:
        try:
            active_subs = stripe.Subscription.list(
                customer=customer_id, status="active", limit=10
            ).get("data", [])
            for sub in active_subs:
                stripe.Subscription.cancel(sub["id"])
                canceled_subscriptions.append(sub["id"])
        except stripe.error.StripeError as exc:
            # El reembolso ya se hizo, pero la suscripcion remota PUEDE
            # SEGUIR COBRANDO. No ocultar esto: se persiste como trabajo
            # pendiente, se conserva el id de suscripcion y la respuesta
            # lleva advertencia explicita para cancelacion manual.
            cancellation_error = str(exc)
            logger.error(
                "Stripe subscription cancel after refund error: %s", exc
            )
        if user_id:
            if cancellation_error is None:
                # Listado + cancelacion confirmados (o lista vacia): no hay
                # nada remoto que pueda seguir cobrando.
                fields = {
                    "status": "refunded",
                    "stripe_subscription_id": None,
                    "cancellation_pending": False,
                    "pending_cancellation_sub_ids": [],
                }
                if canceled_subscriptions:
                    fields["last_canceled_subscription_id"] = (
                        canceled_subscriptions[-1]
                    )
                billing_store.upsert_record(user_id, **fields)
            else:
                # Cancelacion NO confirmada: conservar el id (sin el no hay
                # forma de cancelar despues) y registrar el trabajo durable
                # POR IDENTIFICADOR, para que una recontratacion posterior
                # no lo descarte y el reintento sepa exactamente que cerrar.
                fields = {
                    "status": "refunded",
                    "cancellation_pending": True,
                }
                prev_sub = (_record or {}).get("stripe_subscription_id")
                if prev_sub:
                    pending_ids = [
                        s for s in ((_record or {}).get("pending_cancellation_sub_ids") or []) if s
                    ]
                    if prev_sub not in pending_ids:
                        pending_ids.append(prev_sub)
                    fields["pending_cancellation_sub_ids"] = pending_ids
                billing_store.upsert_record(user_id, **fields)

    response: dict = {
        "refund_id": refund.get("id"),
        "amount": refund.get("amount"),
        "status": refund.get("status"),
        "canceled_subscriptions": canceled_subscriptions,
    }
    if cancellation_error:
        response["warning"] = (
            "El reembolso se creo, pero NO se pudo confirmar la cancelacion "
            "de la suscripcion en Stripe: puede continuar cobrando. "
            "Cancelacion pendiente registrada; no repetir el reembolso."
        )
        response["cancellation_error"] = cancellation_error
    return response
