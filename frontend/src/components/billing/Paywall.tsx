"use client";

import { useState } from "react";
import {
  ArrowRight,
  CheckCircle2,
  CreditCard,
  Loader2,
  RefreshCw,
  Shield,
  Sparkles,
} from "lucide-react";
import { createCheckout, openPortal } from "@/lib/api";
import { useBilling } from "./BillingContext";

const INCLUDED = [
  "Análisis de enlaces, correos y mensajes sospechosos",
  "Códigos QR, archivos, imágenes y audio",
  "Verificación de filtraciones de tus datos",
  "Chequeo de servidores e inteligencia de amenazas",
  "Asistente de seguridad con IA",
  "Panel con historial y recomendaciones",
];

export default function Paywall() {
  const { refresh } = useBilling();
  const [busy, setBusy] = useState<"checkout" | "portal" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubscribe = async () => {
    setBusy("checkout");
    setError(null);
    try {
      const { checkout_url } = await createCheckout();
      window.location.assign(checkout_url);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "No se pudo iniciar el pago. Inténtalo de nuevo."
      );
      setBusy(null);
    }
  };

  const handlePortal = async () => {
    setBusy("portal");
    setError(null);
    try {
      const { portal_url } = await openPortal();
      window.location.assign(portal_url);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "No se pudo abrir el portal de facturación.";
      // Sin cuenta de facturación todavía: no es un error grave.
      if (/404|no.*(encontr|billing)/i.test(message)) {
        setError("Aún no tienes una cuenta de pago asociada. Usa «Suscribirme» para empezar.");
      } else {
        setError(message);
      }
      setBusy(null);
    }
  };

  return (
    <div className="mx-auto w-full max-w-2xl animate-fade-in-up">
      <div className="gradient-border glow-cyan rounded-2xl p-7 text-center sm:p-9">
        <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10">
          <Shield className="h-7 w-7 text-cyan-400" />
        </span>
        <h2 className="mt-5 text-xl font-bold text-white sm:text-2xl">
          Tu prueba gratuita terminó
        </h2>
        <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-400">
          Sigue protegiéndote con CENTINELA Pro. Un solo plan, todo incluido,
          sin permanencias.
        </p>

        <div className="mt-6 flex items-end justify-center gap-1">
          <span className="text-4xl font-bold text-white">US$16</span>
          <span className="pb-1.5 text-sm text-slate-500">/mes</span>
        </div>
        <p className="mt-1 flex items-center justify-center gap-1.5 text-xs text-slate-500">
          <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
          Renovación mensual automática · Cancela cuando quieras
        </p>

        <ul className="mx-auto mt-6 max-w-md space-y-2.5 text-left">
          {INCLUDED.map((feature) => (
            <li
              key={feature}
              className="flex items-start gap-2.5 text-sm text-slate-300"
            >
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />
              {feature}
            </li>
          ))}
        </ul>

        <div className="mt-7 flex flex-col items-center gap-3">
          <button
            onClick={handleSubscribe}
            disabled={busy !== null}
            className="flex h-12 w-full max-w-sm items-center justify-center gap-2 rounded-lg bg-cyan-600 text-sm font-semibold text-white transition-colors hover:bg-cyan-500 disabled:opacity-60"
          >
            {busy === "checkout" ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <ArrowRight className="h-4 w-4" />
            )}
            Suscribirme
          </button>
          <button
            onClick={handlePortal}
            disabled={busy !== null}
            className="text-xs text-slate-500 underline-offset-2 transition-colors hover:text-cyan-300 hover:underline disabled:opacity-60"
          >
            ¿Ya tienes cuenta de pago? Actualizar método
          </button>
        </div>

        {error && (
          <div className="mt-4 flex flex-col items-center gap-2">
            <p className="rounded-lg border border-red-500/20 bg-red-500/5 px-4 py-2.5 text-xs text-red-400">
              {error}
            </p>
            <button
              onClick={refresh}
              className="flex items-center gap-1.5 text-xs text-slate-500 transition-colors hover:text-cyan-300"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Reintentar
            </button>
          </div>
        )}

        <p className="mt-5 flex items-center justify-center gap-1.5 text-xs text-slate-600">
          <CreditCard className="h-3.5 w-3.5" />
          Pagos procesados por Stripe · No almacenamos datos de tu tarjeta
        </p>
      </div>
    </div>
  );
}
