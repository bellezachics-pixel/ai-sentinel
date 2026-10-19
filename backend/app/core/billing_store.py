"""
Estado de facturacion POR USUARIO, persistido en JSON (data/billing.json).

Mapea user_id local -> datos de la suscripcion Stripe:
{
  "stripe_customer_id": str | null,
  "stripe_subscription_id": str | null,
  "status": str,                # active|trialing|past_due|canceled|refunded|incomplete|none
  "trial_end": str | null,      # ISO 8601
  "current_period_end": str | null,
  "cancel_at_period_end": bool,
  "last_payment_at": str,       # ISO 8601 (ultimo invoice.payment_succeeded)
  "last_payment_amount": int,   # monto pagado en centavos
  "last_refund_at": str,        # ISO 8601 (ultimo reembolso registrado)
  "last_refund_amount": int,    # monto reembolsado en centavos
  "last_refund_id": str,        # re_... de Stripe
  "updated_at": str             # ISO 8601
}

Los campos nuevos son OPCIONALES: los registros existentes sin ellos
siguen siendo validos (se completan al llegar los eventos/webhooks).

Notas:
- Reutiliza la resolucion de DATA_DIR de user_store (mismo directorio).
- Thread-safe (lock) y escritura atomica (tmp + os.replace).
- Solo apto para proceso UNICO (ver Dockerfile: --workers 1).
En produccion se recomienda PostgreSQL/Redis.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime
from typing import Optional

from app.core.user_store import DATA_DIR

BILLING_FILE = DATA_DIR / "billing.json"

_lock = threading.Lock()
_cache: Optional[dict[str, dict]] = None

# Deduplicacion de eventos de webhook (Stripe puede reentregar).
# Archivo aparte: una lista acotada de IDs ya procesados (FIFO).
EVENTS_FILE = DATA_DIR / "webhook_events.json"
_events_cache: Optional[list] = None
_MAX_TRACKED_EVENTS = 2000

# Estados de suscripcion que otorgan acceso completo.
ACCESS_GRANTING_STATUSES = ("active", "trialing")

# Estados "terminales" o de suscripcion pagada que un checkout viejo
# NO debe pisar: reentregar un checkout.session.completed antiguo no
# puede resucitar una cancelacion/reembolso ni rebajar una suscripcion
# activa a "trialing".
CHECKOUT_PROTECTED_STATUSES = ("active", "canceled", "refunded", "past_due")


def _load() -> dict[str, dict]:
    if not BILLING_FILE.exists():
        return {}
    try:
        with open(BILLING_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return {
            str(user_id): rec
            for user_id, rec in data.items()
            if isinstance(rec, dict)
        }
    except Exception:
        return {}


def _save(data: dict[str, dict]):
    BILLING_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = BILLING_FILE.with_name(BILLING_FILE.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, BILLING_FILE)


def _get() -> dict[str, dict]:
    global _cache
    if _cache is None:
        _cache = _load()
    return _cache


def get_record(user_id: str) -> dict:
    """Devuelve una COPIA del registro de facturacion del usuario (o {})."""
    if not user_id:
        return {}
    with _lock:
        return dict(_get().get(user_id, {}))


def get_record_by_customer(stripe_customer_id: str) -> tuple[str, dict] | tuple[None, None]:
    """Localiza un registro por stripe_customer_id -> (user_id, record)."""
    if not stripe_customer_id:
        return None, None
    with _lock:
        for user_id, rec in _get().items():
            if rec.get("stripe_customer_id") == stripe_customer_id:
                return user_id, dict(rec)
    return None, None


def upsert_record(user_id: str, **fields):
    """Crea o actualiza campos del registro de facturacion del usuario."""
    if not user_id:
        return
    with _lock:
        data = _get()
        rec = data.setdefault(user_id, {})
        rec.update(fields)
        rec["updated_at"] = datetime.utcnow().isoformat()
        _save(data)


def delete_record(user_id: str):
    """Elimina el registro (ej. suscripcion cancelada y limpiada)."""
    if not user_id:
        return
    with _lock:
        data = _get()
        if user_id in data:
            del data[user_id]
            _save(data)


def reset_cache_for_tests():
    """Limpia el cache en memoria (solo para tests)."""
    global _cache
    with _lock:
        _cache = None


# ---------------------------------------------------------------
# Deduplicacion de eventos de webhook
# ---------------------------------------------------------------

def _load_events() -> list:
    if not EVENTS_FILE.exists():
        return []
    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [e for e in data if isinstance(e, str)] if isinstance(data, list) else []
    except Exception:
        return []


def _get_events() -> list:
    global _events_cache
    if _events_cache is None:
        _events_cache = _load_events()
    return _events_cache


def has_event(event_id: str) -> bool:
    """True si el evento ya fue procesado (dedup de reentregas de Stripe)."""
    if not event_id:
        return False
    with _lock:
        return event_id in _get_events()


def record_event(event_id: str):
    """Marca un evento como procesado. Llamar SOLO tras procesarlo con exito."""
    if not event_id:
        return
    with _lock:
        events = _get_events()
        if event_id in events:
            return
        events.append(event_id)
        if len(events) > _MAX_TRACKED_EVENTS:
            del events[: len(events) - _MAX_TRACKED_EVENTS]
        EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = EVENTS_FILE.with_name(EVENTS_FILE.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(events, f)
        os.replace(tmp, EVENTS_FILE)


def reset_events_cache_for_tests():
    global _events_cache
    with _lock:
        _events_cache = None
