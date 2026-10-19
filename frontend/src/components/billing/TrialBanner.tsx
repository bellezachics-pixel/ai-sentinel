"use client";

import { useState } from "react";
import { Sparkles, X } from "lucide-react";
import { daysUntil, formatPlanDate } from "./BillingContext";

const DISMISS_KEY = "guardiaflow_trial_banner_dismissed";

interface TrialBannerProps {
  trialEnd: string | null;
}

export default function TrialBanner({ trialEnd }: TrialBannerProps) {
  // Inicializacion perezosa: lee localStorage en el primer render, sin
  // necesidad de un efecto (evita setState sincrono en useEffect).
  const [dismissed, setDismissed] = useState(() => {
    try {
      return window.localStorage.getItem(DISMISS_KEY) === "1";
    } catch {
      // localStorage unavailable (private mode, etc.): keep the banner visible.
      return false;
    }
  });

  if (dismissed) return null;

  const days = daysUntil(trialEnd);
  const endDate = formatPlanDate(trialEnd);

  const dismiss = () => {
    setDismissed(true);
    try {
      window.localStorage.setItem(DISMISS_KEY, "1");
    } catch {
      // Ignore persistence failures.
    }
  };

  return (
    <div className="flex items-center gap-3 border-b border-cyan-500/20 bg-cyan-500/10 px-4 py-2.5 sm:px-6">
      <Sparkles className="h-4 w-4 shrink-0 text-cyan-400" />
      <p className="min-w-0 flex-1 text-xs text-cyan-200 sm:text-sm">
        <span className="font-semibold">Prueba gratuita:</span>{" "}
        {days !== null && days <= 0
          ? "tu prueba termina hoy"
          : days !== null
            ? `te quedan ${days} ${days === 1 ? "día" : "días"}`
            : "estás en tu período de prueba"}
        {endDate ? ` (hasta el ${endDate})` : ""}. Al terminar, el plan es de
        US$16/mes; cancela antes sin ningún cargo desde tu panel.
      </p>
      <button
        onClick={dismiss}
        aria-label="Cerrar aviso de prueba"
        className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-cyan-300/70 transition-colors hover:bg-cyan-500/10 hover:text-cyan-200"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
