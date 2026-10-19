"use client";

import { useEffect } from "react";
import Link from "next/link";
import { ArrowLeft, ArrowRight, Shield, XCircle } from "lucide-react";
import { getAccessToken } from "@/lib/api";

export default function BillingCancelPage() {
  useEffect(() => {
    if (!getAccessToken()) {
      window.location.replace("/app");
    }
  }, []);

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#0a0e1a] p-6">
      <div className="w-full max-w-md rounded-xl border border-[#1e293b] bg-[#0d1117] p-8 text-center">
        <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-xl border border-slate-500/30 bg-slate-500/10">
          <XCircle className="h-7 w-7 text-slate-400" />
        </span>
        <h1 className="mt-5 text-xl font-bold text-white">
          Pago cancelado
        </h1>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          No se hizo ningún cargo. Cerraste la ventana de pago antes de
          completar la suscripción, y eso está perfecto: tu cuenta sigue igual.
        </p>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          Si cambias de opinión, puedes suscribirte cuando quieras desde tu
          panel o desde la página de precios.
        </p>

        <div className="mt-6 flex flex-col gap-3">
          <Link
            href="/app"
            className="flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 text-sm font-medium text-white transition-colors hover:bg-cyan-500"
          >
            <ArrowLeft className="h-4 w-4" />
            Volver a mi panel
          </Link>
          <Link
            href="/#precios"
            className="flex h-11 w-full items-center justify-center gap-2 rounded-lg border border-[#1e293b] text-sm font-medium text-slate-300 transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
          >
            Ver precios
            <ArrowRight className="h-4 w-4" />
          </Link>
        </div>

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
