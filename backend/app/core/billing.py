"""
Logica de acceso de CENTINELA (billing).

Reglas de negocio:
- Trial local: 3 dias gratis desde `trial_start` (se graba al registrarse).
- Suscripcion Stripe: estados `active` y `trialing` otorgan acceso.
- Modo "trial-only": si Stripe NO esta configurado (sin STRIPE_SECRET_KEY),
  solo el trial local otorga acceso y /billing/checkout responde 503.

El cliente Stripe se inicializa de forma LAZY (nunca al importar el modulo
ni al arrancar la app sin clave). SOLO se soporta modo TEST: jamas pongas
una clave live de Stripe en estas variables.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

import stripe
from fastapi import Depends, HTTPException, status

from app.core import billing_store
from app.core.auth import UserInDB, require_analysis_access
from app.core.config import settings

TRIAL_DAYS = 3
PLAN_PRICE_LABEL = "US$16/mes"

# Estados de suscripcion que bloquean el acceso de forma EXPLICITA: aunque
# el trial local de 3 dias siga vigente, NO otorgan acceso (un reembolso
# completo o una cancelacion no pueden ser resucitados por el trial).
ACCESS_BLOCKING_STATUSES = ("refunded", "canceled")

# Cache del cliente (modulo `stripe` con api_key fijada). Solo se pobla
# cuando STRIPE_SECRET_KEY existe; si no hay clave se devuelve None SIEMPRE
# (sin cachear) para que activar la clave en caliente (tests) funcione.
_stripe_ready = False


def stripe_configured() -> bool:
    return bool(settings.STRIPE_SECRET_KEY)


def get_stripe_client():
    """Cliente Stripe lazy. None si no hay clave configurada."""
    global _stripe_ready
    if not stripe_configured():
        return None
    if not _stripe_ready:
        stripe.api_key = settings.STRIPE_SECRET_KEY
        _stripe_ready = True
    return stripe


def reset_stripe_client_for_tests():
    """Olvida el estado del cliente (solo para tests)."""
    global _stripe_ready
    _stripe_ready = False
    stripe.api_key = None


def trial_end_for(user: UserInDB) -> Optional[datetime]:
    """Fin del trial local (trial_start + 3 dias), o None si no hay trial."""
    start = getattr(user, "trial_start", None)
    if not start:
        return None
    return start + timedelta(days=TRIAL_DAYS)


def trial_active(user: UserInDB) -> bool:
    end = trial_end_for(user)
    return end is not None and datetime.utcnow() < end


def has_access(user: UserInDB, record: Optional[dict] = None) -> bool:
    """
    Acceso completo si:
    (a) hay suscripcion Stripe activa/trialing (segun store/webhooks), o
    (b) el trial local de 3 dias sigue vigente.
    Excepcion: status "refunded"/"canceled" bloquea SIEMPRE (ni el trial
    ni la suscripcion resucitan el acceso tras un reembolso/cancelacion).
    Sin Stripe configurado: modo trial-only (solo la rama (b)).
    """
    if user is not None and user.is_admin:
        return True
    if record is None:
        record = billing_store.get_record(user.id) if user else {}
    # Reembolsado/cancelado: sin acceso, aunque el trial local siga vivo.
    if record.get("status") in ACCESS_BLOCKING_STATUSES:
        return False
    if stripe_configured() and record.get("status") in billing_store.ACCESS_GRANTING_STATUSES:
        return True
    return trial_active(user) if user else False


async def require_access(
    user: Optional[UserInDB] = Depends(require_analysis_access),
) -> Optional[UserInDB]:
    """
    Dependencia de enforcement para rutas de analisis/chat/dashboard.

    Comportamiento (documentado):
    - REQUIRE_AUTH_FOR_ANALYSIS=false y request ANONIMA -> se permite sin
      chequeo de acceso (mismo comportamiento anterior; los tests existentes
      dependen de esto).
    - Usuario autenticado + BILLING_ENFORCE=true -> se exige trial vigente o
      suscripcion; si no, 402 trial_expirado_o_suscripcion_requerida.
    - BILLING_ENFORCE=false -> cualquier usuario autenticado pasa.
    - Admin (is_admin) siempre pasa.
    """
    if user is None:
        return None
    if not settings.BILLING_ENFORCE:
        return user
    if not has_access(user):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="trial_expirado_o_suscripcion_requerida",
        )
    return user
