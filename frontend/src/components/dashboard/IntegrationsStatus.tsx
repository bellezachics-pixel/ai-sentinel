"use client";

import { CheckCircle, KeyRound, XCircle } from "lucide-react";
import type { IntegrationsStatus as IntegrationsStatusType } from "@/lib/api";
import { cn } from "@/lib/utils";

interface IntegrationsStatusProps {
  integrations: IntegrationsStatusType | null;
  loading?: boolean;
}

const LABELS: Record<string, string> = {
  openai_chat: "Sentinel IA chat",
  openai_vision: "Detector IA imagen",
  virustotal: "Archivos y URLs",
  google_fact_check: "Noticias",
  google_login: "Login Google",
  numverify: "Telefono",
  twilio_lookup: "Telefono avanzado",
  urlscan: "URLScan",
  abuseipdb: "AbuseIPDB",
};

const ORDER = [
  "openai_chat",
  "openai_vision",
  "virustotal",
  "google_fact_check",
  "google_login",
  "numverify",
  "twilio_lookup",
  "urlscan",
  "abuseipdb",
];

export default function IntegrationsStatus({
  integrations,
  loading = false,
}: IntegrationsStatusProps) {
  const items = ORDER.map((key) => ({ key, value: integrations?.[key] }));
  const configuredCount = items.filter((item) => item.value?.configured).length;

  return (
    <div>
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-300">
            Integraciones
          </h3>
          <p className="mt-1 text-xs text-slate-500">
            APIs reales listas para la app
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-[#1e293b] bg-[#0a0e1a] px-3 py-1.5">
          <KeyRound className="h-3.5 w-3.5 text-cyan-400" />
          <span className="text-xs text-slate-300">
            {loading ? "..." : `${configuredCount}/${items.length}`}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
        {items.map(({ key, value }) => {
          const configured = Boolean(value?.configured);
          const detail = value?.model || value?.country || value?.provider || "Pendiente";

          return (
            <div
              key={key}
              className={cn(
                "rounded-lg border bg-[#0a0e1a] p-3",
                configured ? "border-emerald-500/20" : "border-amber-500/20"
              )}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium text-slate-200">
                    {LABELS[key] || key}
                  </p>
                  <p className="mt-1 truncate text-[11px] text-slate-500">
                    {detail}
                  </p>
                </div>
                {configured ? (
                  <CheckCircle className="h-4 w-4 shrink-0 text-emerald-400" />
                ) : (
                  <XCircle className="h-4 w-4 shrink-0 text-amber-400" />
                )}
              </div>
              <p
                className={cn(
                  "mt-3 text-[11px] font-medium",
                  configured ? "text-emerald-400" : "text-amber-400"
                )}
              >
                {configured ? "Activa" : "Falta API key"}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
