"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { DashboardStats, IntegrationsStatus as IntegrationsStatusType } from "@/lib/api";
import StatsCards from "./StatsCards";
import RiskGauge from "./RiskGauge";
import ThreatDistribution from "./ThreatDistribution";
import RecentAnalyses from "./RecentAnalyses";
import NetworkStatus from "./NetworkStatus";
import IntegrationsStatus from "./IntegrationsStatus";
import PlanStatusCard from "@/components/billing/PlanStatusCard";
import PaymentHistory from "@/components/billing/PaymentHistory";
import { useBilling } from "@/components/billing/BillingContext";
import { RefreshCw, Loader2, AlertTriangle, ShieldCheck, Search } from "lucide-react";

type LoadStatus = "loading" | "error" | "ready";

export default function Dashboard() {
  const { state: billingState } = useBilling();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [integrations, setIntegrations] =
    useState<IntegrationsStatusType | null>(null);
  const [status, setStatus] = useState<LoadStatus>("loading");

  const fetchStats = async () => {
    setStatus("loading");
    try {
      const [data, integrationData] = await Promise.all([
        api.getDashboardStats(),
        api.getIntegrationsStatus(),
      ]);
      setStats(data);
      setIntegrations(integrationData);
      setStatus("ready");
    } catch {
      setStats(null);
      setIntegrations(null);
      setStatus("error");
    }
  };

  useEffect(() => {
    // La carga se difiere un tick para no llamar setState de forma
    // sincrona dentro del efecto (regla react-hooks/set-state-in-effect).
    const timer = setTimeout(() => {
      fetchStats();
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  const overallRisk = stats
    ? stats.risk_distribution.critical > 0
      ? Math.min(
          100,
          50 + stats.risk_distribution.critical * 2 + stats.risk_distribution.high
        )
      : stats.risk_distribution.high > 0
      ? Math.min(75, 30 + stats.risk_distribution.high)
      : stats.risk_distribution.medium > 0
      ? Math.min(50, 10 + Math.floor(stats.risk_distribution.medium / 10))
      : 8
    : 0;

  return (
    <div className="space-y-6 animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">
            Panel de Control
          </h2>
          <p className="text-sm text-slate-500 mt-0.5">
            Resumen de seguridad en tiempo real
          </p>
        </div>
        <button
          onClick={fetchStats}
          disabled={status === "loading"}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#111827] border border-[#1e293b] text-sm text-slate-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors disabled:opacity-50"
        >
          <RefreshCw
            className={`w-4 h-4 ${status === "loading" ? "animate-spin" : ""}`}
          />
          Actualizar
        </button>
      </div>

      {/* Loading */}
      {status === "loading" && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-12 flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 animate-spin text-cyan-400" />
          <p className="text-sm text-slate-400">Cargando tu panel de seguridad...</p>
        </div>
      )}

      {/* Error */}
      {status === "error" && (
        <div className="rounded-xl bg-red-500/5 border border-red-500/20 p-8 flex flex-col items-center gap-4 text-center">
          <AlertTriangle className="w-10 h-10 text-red-400" />
          <div>
            <p className="text-sm font-semibold text-red-400">
              No se pudo conectar con el servidor de análisis
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Revisa tu conexión e inténtalo de nuevo.
            </p>
          </div>
          <button
            onClick={fetchStats}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 text-sm font-medium text-white transition-colors hover:bg-cyan-500"
          >
            <RefreshCw className="w-4 h-4" />
            Reintentar
          </button>
        </div>
      )}

      {/* Ready */}
      {status === "ready" && stats && (
        <>
          {/* Empty state */}
          {stats.total_scans === 0 && (
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4 text-center">
              <ShieldCheck className="w-10 h-10 text-emerald-400" />
              <div>
                <p className="text-sm font-semibold text-slate-200">
                  Aún no hay análisis
                </p>
                <p className="text-xs text-slate-500 mt-1 max-w-md">
                  Cuando ejecutes tu primer escaneo, aquí verás un resumen de tu
                  seguridad, las amenazas detectadas y tus análisis recientes.
                </p>
              </div>
              <a
                href="#"
                onClick={(e) => e.preventDefault()}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600/10 border border-cyan-500/30 text-sm text-cyan-400"
              >
                <Search className="w-4 h-4" />
                Usa &quot;Analizar Todo&quot; en el menú para empezar
              </a>
            </div>
          )}

          {/* Stats Cards */}
          <StatsCards
            totalScans={stats.total_scans}
            threatsDetected={stats.threats_detected}
            activeMonitors={stats.active_monitors}
            networkSecure={stats.network_status.is_secure}
          />

          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <IntegrationsStatus integrations={integrations} loading={false} />
          </div>

          {/* Middle Row: Risk Gauge + Threat Distribution + Network Status + Plan */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 xl:grid-cols-4 gap-4">
            {/* Risk Gauge */}
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 flex items-center justify-center">
              <RiskGauge score={overallRisk} />
            </div>

            {/* Threat Distribution */}
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
              <ThreatDistribution distribution={stats.risk_distribution} />
            </div>

            {/* Network Status */}
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
              <NetworkStatus
                isSecure={stats.network_status.is_secure}
                riskIndicators={stats.network_status.risk_indicators}
              />
            </div>

            {/* Plan / Billing status */}
            {billingState.kind === "ready" && (
              <>
                <PlanStatusCard billing={billingState.billing} />
                <PaymentHistory />
              </>
            )}
          </div>

          {/* Recent Analyses */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">
              Análisis Recientes
            </h3>
            <RecentAnalyses analyses={stats.recent_analyses} />
          </div>
        </>
      )}
    </div>
  );
}
