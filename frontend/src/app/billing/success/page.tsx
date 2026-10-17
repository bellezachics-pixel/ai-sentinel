"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowRight,
  CheckCircle2,
  Loader2,
  RefreshCw,
  Shield,
} from "lucide-react";
import { getAccessToken, getBillingStatus } from "@/lib/api";

type ConfirmState = "loading" | "confirmed" | "pending";

function BillingSuccessContent() {
  const searchParams = useSearchParams();
  const sessionId = searchParams.get("session_id");
  const [state, setState] = useState<ConfirmState>("loading");

  useEffect(() => {
    if (!getAccessToken()) {
      window.location.replace("/app");
      return;
    }
    let cancelled = false;
    getBillingStatus()
      .then((billing) => {
        if (cancelled) return;
        setState(billing.has_access ? "confirmed" : "pending");
      })
      .catch(() => {
        if (!cancelled) setState("pending");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const retry = () => {
    setState("loading");
    getBillingStatus()
      .then((billing) =>
        setState(billing.has_access ? "confirmed" : "pending")
      )
      .catch(() => setState("pending"));
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#0a0e1a] p-6">
      <div className="w-full max-w-md rounded-xl border border-[#1e293b] bg-[#0d1117] p-8 text-center">
        <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-xl border border-emerald-500/30 bg-emerald-500/10">
          {state === "loading" ? (
            <Loader2 className="h-7 w-7 animate-spin text-emerald-400" />
          ) : (
            <CheckCircle2 className="h-7 w-7 text-emerald-400" />
          )}
        </span>

        {state === "loading" && (
          <>
            <h1 className="mt-5 text-xl font-bold text-white">
              Confirmando tu suscripción...
            </h1>
            <p className="mt-2 text-sm leading-6 text-slate-400">
              Estamos verificando tu pago con Stripe. Esto toma solo unos
              segundos.
            </p>
          </>
        )}

        {state === "confirmed" && (
          <>
            <h1 className="mt-5 text-xl font-bold text-white">
              ¡Bienvenida a Guardia Flow Pro!
            </h1>
            <p className="mt-2 text-sm leading-6 text-slate-400">
              Tu suscripción está activa. Ya puedes usar todas las herramientas
              de protección sin límites.
            </p>
            <Link
              href="/app"
              className="mt-6 flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 text-sm font-medium text-white transition-colors hover:bg-cyan-500"
            >
              Ir a mi panel
              <ArrowRight className="h-4 w-4" />
            </Link>
          </>
        )}

        {state === "pending" && (
          <>
            <h1 className="mt-5 text-xl font-bold text-white">
              Estamos procesando tu pago
            </h1>
            <p className="mt-2 text-sm leading-6 text-slate-400">
              Stripe nos confirmó la sesión
              {sessionId ? ` (${sessionId.slice(0, 14)}...)` : ""}, pero tu
              acceso aún no aparece activo. Puede tardar unos minutos en
              reflejarse.
            </p>
            <div className="mt-6 flex flex-col gap-3">
              <button
                onClick={retry}
                className="flex h-11 w-full items-center justify-center gap-2 rounded-lg border border-[#1e293b] text-sm font-medium text-slate-300 transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
              >
                <RefreshCw className="h-4 w-4" />
                Verificar de nuevo
              </button>
              <Link
                href="/app"
                className="flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 text-sm font-medium text-white transition-colors hover:bg-cyan-500"
              >
                Ir a mi panel
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
            <p className="mt-4 text-xs text-slate-600">
              ¿Pasaron más de 15 minutos? Escríbenos a soporte@guardiaflow.com con tu
              correo de cuenta.
            </p>
          </>
        )}

        <Link
          href="/"
          className="mt-6 inline-flex items-center gap-2 text-xs text-slate-600 transition-colors hover:text-cyan-300"
        >
          <Shield className="h-3.5 w-3.5" />
          Volver a guardiaflow.com
        </Link>
      </div>
    </main>
  );
}

export default function BillingSuccessPage() {
  return (
    <Suspense
      fallback={
        <main className="flex min-h-screen items-center justify-center bg-[#0a0e1a]">
          <Loader2 className="h-8 w-8 animate-spin text-cyan-400" />
        </main>
      }
    >
      <BillingSuccessContent />
    </Suspense>
  );
}
