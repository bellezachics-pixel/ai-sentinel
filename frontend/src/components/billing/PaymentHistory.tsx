"use client";

import { useEffect, useState } from "react";
import { FileText, Receipt, RefreshCw } from "lucide-react";
import { getPayments, type PaymentItem } from "@/lib/api";
import { formatPlanDate } from "./BillingContext";

function formatAmount(amount: number, currency: string): string {
  try {
    return new Intl.NumberFormat("es", {
      style: "currency",
      currency: currency.toUpperCase(),
    }).format(amount / 100);
  } catch {
    return `${(amount / 100).toFixed(2)} ${currency.toUpperCase()}`;
  }
}

function statusLabel(status: string): { label: string; tone: string } {
  switch (status) {
    case "succeeded":
      return { label: "Confirmado", tone: "text-emerald-400" };
    case "pending":
      return { label: "Pendiente", tone: "text-amber-400" };
    case "failed":
      return { label: "Rechazado", tone: "text-red-400" };
    case "refunded":
      return { label: "Reembolsado", tone: "text-slate-400" };
    case "canceled":
      return { label: "Cancelado", tone: "text-slate-400" };
    default:
      return { label: status, tone: "text-slate-400" };
  }
}

/**
 * Historial de pagos del cliente (Stripe). Muestra confirmaciones de pago
 * con enlace al recibo oficial cuando Stripe lo provee.
 */
export default function PaymentHistory() {
  const [payments, setPayments] = useState<PaymentItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setError(null);
    try {
      const data = await getPayments();
      setPayments(data.payments);
    } catch (err) {
      // 503 = pasarela no configurada aún: no es un error que rompa la UI.
      const msg = err instanceof Error ? err.message : "";
      setError(msg || "No se pudo cargar el historial de pagos.");
      setPayments(null);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="rounded-xl border border-[#1e293b] bg-[#111827] p-5">
      <div className="flex items-center gap-2">
        <Receipt className="h-4 w-4 text-slate-500" />
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">
          Historial de pagos
        </p>
      </div>

      {error && (
        <div className="mt-3 flex items-center gap-2">
          <p className="min-w-0 flex-1 text-[11px] text-slate-500">{error}</p>
          <button
            onClick={load}
            aria-label="Reintentar"
            className="text-slate-500 hover:text-cyan-300"
          >
            <RefreshCw className="h-3 w-3" />
          </button>
        </div>
      )}

      {!error && payments === null && (
        <p className="mt-3 text-xs text-slate-500">Cargando…</p>
      )}

      {!error && payments !== null && payments.length === 0 && (
        <p className="mt-3 text-xs leading-5 text-slate-500">
          Aún no hay pagos registrados. Durante la prueba gratuita no se
          genera ningún cargo.
        </p>
      )}

      {!error && payments !== null && payments.length > 0 && (
        <ul className="mt-3 space-y-2">
          {payments.map((p) => {
            const st = statusLabel(p.status);
            return (
              <li
                key={p.id}
                className="flex items-center justify-between gap-3 rounded-lg border border-[#1e293b] bg-[#0a0e1a] px-3 py-2"
              >
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium text-white">
                    {p.description || "Pago CENTINELA Pro"}
                  </p>
                  <p className="text-[11px] text-slate-500">
                    {formatPlanDate(p.date) ?? p.date} ·{" "}
                    <span className={st.tone}>{st.label}</span>
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-3">
                  <span className="text-xs font-semibold text-white">
                    {formatAmount(p.amount, p.currency)}
                  </span>
                  {p.receipt_url && (
                    <a
                      href={p.receipt_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 text-[11px] text-cyan-300 hover:text-cyan-200"
                    >
                      <FileText className="h-3 w-3" />
                      Recibo
                    </a>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
