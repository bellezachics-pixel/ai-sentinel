"use client";

import { useState } from "react";
import {
  AlertTriangle,
  CalendarClock,
  CreditCard,
  Crown,
  Loader2,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { createCheckout, openPortal, type BillingStatus } from "@/lib/api";
import { daysUntil, formatPlanDate } from "./BillingContext";

const price = (billing: BillingStatus) => billing.plan_price || "US$16/mes";

export default function PlanStatusCard({ billing }: { billing: BillingStatus }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const goToPortal = async () => {
    setBusy(true);
    setError(null);
    try {
      const { portal_url } = await openPortal();
      window.location.assign(portal_url);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudo abrir el portal de facturación."
      );
      setBusy(false);
    }
  };

  const goToCheckout = async () => {
    setBusy(true);
    setError(null);
    try {
      const { checkout_url } = await createCheckout();
      window.location.assign(checkout_url);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "No se pudo iniciar el pago."
      );
      setBusy(false);
    }
  };

  const periodEnd = formatPlanDate(billing.current_period_end);
  const trialEnd = formatPlanDate(billing.trial_end);
  const daysLeft = daysUntil(billing.trial_end);

  let icon = <ShieldCheck className="h-5 w-5 text-slate-500" />;
  let title = "Sin suscripción";
  let tone = "text-slate-400";
  let body: React.ReactNode = (
    <p>
      Activa Guardia Flow Pro para seguir usando todas las herramientas (
      {price(billing)}).
    </p>
  );
  let action: { label: string; onClick: () => void } | null = {
    label: "Suscribirme",
    onClick: goToCheckout,
  };

  if (billing.status === "trialing") {
    icon = <CalendarClock className="h-5 w-5 text-cyan-400" />;
    title = "Prueba gratuita";
    tone = "text-cyan-400";
    body = (
      <p>
        {daysLeft !== null
          ? `Te quedan ${daysLeft} ${daysLeft === 1 ? "día" : "días"} de prueba. `
          : "Estás en tu período de prueba. "}
        {trialEnd ? `Primer cobro: ${trialEnd} (${price(billing)}).` : ""}
      </p>
    );
    action = { label: "Gestionar suscripción", onClick: goToPortal };
  } else if (billing.status === "active") {
    icon = <Crown className="h-5 w-5 text-emerald-400" />;
    title = "Plan Pro activo";
    tone = "text-emerald-400";
    body = (
      <p>
        {billing.cancel_at_period_end
          ? `Cancelaste tu plan; conservas el acceso hasta el ${periodEnd ?? "final del período"}.`
          : `Tu plan se renueva ${periodEnd ? `el ${periodEnd}` : "al final del período"} (${price(billing)}).`}
      </p>
    );
    action = { label: "Gestionar suscripción", onClick: goToPortal };
  } else if (billing.status === "past_due") {
    icon = <AlertTriangle className="h-5 w-5 text-amber-400" />;
    title = "Pago pendiente";
    tone = "text-amber-400";
    body = (
      <p>
        Hubo un problema con tu método de pago. Actualízalo para no perder el
        acceso.
      </p>
    );
    action = { label: "Actualizar método de pago", onClick: goToPortal };
  } else if (billing.status === "canceled") {
    icon = <XCircle className="h-5 w-5 text-slate-400" />;
    title = "Suscripción cancelada";
    tone = "text-slate-300";
    body = (
      <p>
        Tienes acceso hasta {periodEnd ?? "el final del período en curso"}.
        Vuelve cuando quieras.
      </p>
    );
    action = null;
  }

  return (
    <div className="rounded-xl border border-[#1e293b] bg-[#111827] p-5">
      <div className="flex items-center gap-3">
        <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#1e293b] bg-[#0a0e1a]">
          {icon}
        </span>
        <div>
          <p className={`text-xs font-semibold uppercase tracking-wide ${tone}`}>
            {title}
          </p>
          <p className="text-sm font-semibold text-white">
            Guardia Flow Pro · {price(billing)}
          </p>
        </div>
      </div>
      <div className="mt-3 text-xs leading-5 text-slate-400">{body}</div>
      {action && (
        <button
          onClick={action.onClick}
          disabled={busy}
          className="mt-3 flex h-9 w-full items-center justify-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-xs font-medium text-cyan-300 transition-colors hover:bg-cyan-500/20 disabled:opacity-60"
        >
          {busy ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <CreditCard className="h-3.5 w-3.5" />
          )}
          {action.label}
        </button>
      )}
      {error && (
        <div className="mt-2 flex items-center gap-2">
          <p className="min-w-0 flex-1 text-[11px] text-red-400">{error}</p>
          <button
            onClick={() => setError(null)}
            className="text-[11px] text-slate-500 hover:text-cyan-300"
          >
            <RefreshCw className="h-3 w-3" />
          </button>
        </div>
      )}
    </div>
  );
}
