"use client";

import { useState } from "react";
import {
  Network,
  Search,
  Loader2,
  AlertTriangle,
  CheckCircle,
  Globe,
  Fingerprint,
} from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";

export default function NetworkMonitor() {
  const [targetIp, setTargetIp] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleCheck = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.checkNetwork(targetIp.trim() || undefined);
      setResult(data);
    } catch {
      setError(
        "No se pudo verificar la red. Verifica que la API esté activa."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white">Monitor de Red</h2>
        <p className="text-sm text-slate-500 mt-0.5">
          Verifica la integridad de tu conexión de red y detecta anomalías
        </p>
      </div>

      {/* Input */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Network className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCheck()}
              placeholder="IP objetivo (opcional, ej: 192.168.1.1)"
              className="w-full h-11 pl-10 pr-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-colors text-mono"
            />
          </div>
          <button
            onClick={handleCheck}
            disabled={loading}
            className="flex items-center justify-center gap-2 px-6 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Search className="w-4 h-4" />
            )}
            {loading ? "Verificando..." : "Verificar Red"}
          </button>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
            <Network className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <div className="text-center">
            <p className="text-sm text-slate-300">Analizando red...</p>
            <p className="text-xs text-slate-500 mt-1">
              Verificando TLS, DNS, ARP y conectividad
            </p>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-xl bg-red-500/5 border border-red-500/20 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-red-400 font-medium">Error</p>
            <p className="text-xs text-red-400/70 mt-1">{error}</p>
          </div>
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <div className="space-y-4">
          {/* Summary cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 flex flex-col items-center justify-center">
              <RiskGauge score={result.risk_score.total} size={140} />
              <p className="text-xs text-slate-500 mt-2">Puntuación de Riesgo</p>
            </div>

            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-3">Estado de la Red</h3>
              <div className="space-y-2">
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#0a0e1a]/50">
                  <span className="text-xs text-slate-400">Conexión</span>
                  <span className={cn("text-xs font-medium", result.risk_score.level === "low" ? "text-emerald-400" : "text-amber-400")}>
                    {result.risk_score.level === "low" ? "Segura" : "Revisar"}
                  </span>
                </div>
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#0a0e1a]/50">
                  <span className="text-xs text-slate-400">Nivel de riesgo</span>
                  <span className={cn("text-xs font-medium uppercase", getRiskColor(String(result.risk_score.level)))}>
                    {String(result.risk_score.level)}
                  </span>
                </div>
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#0a0e1a]/50">
                  <span className="text-xs text-slate-400">Latencia</span>
                  <span className="text-xs font-medium text-slate-300">
                    {typeof result.metadata?.latency === "number" ? `${result.metadata.latency.toFixed(1)} ms` : "N/A"}
                  </span>
                </div>
              </div>
            </div>

            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-3">Objetivo</h3>
              <div className="space-y-2">
                <div className="p-2.5 rounded-lg bg-[#0a0e1a]/50">
                  <span className="text-[10px] text-slate-500 uppercase block">Target</span>
                  <span className="text-xs text-slate-300 font-mono">{String(result.metadata?.target || result.target)}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-[#0a0e1a]/50">
                  <span className="text-[10px] text-slate-500 uppercase block">Hostname</span>
                  <span className="text-xs text-slate-300 font-mono">{String(result.metadata?.hostname || "N/A")}</span>
                </div>
              </div>
            </div>
          </div>

          {/* DNS info */}
          {result.metadata?.dns && (
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" /> DNS
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-3 rounded-lg bg-[#0a0e1a]/50">
                  <span className="text-[10px] text-slate-500 uppercase block mb-1">Resolver</span>
                  <span className="text-xs text-slate-300 font-mono">{String((result.metadata.dns as any).resolver || "Sistema")}</span>
                </div>
                <div className="p-3 rounded-lg bg-[#0a0e1a]/50">
                  <span className="text-[10px] text-slate-500 uppercase block mb-1">IPs resueltas</span>
                  <span className="text-xs text-slate-300 font-mono">
                    {Array.isArray((result.metadata.dns as any).resolved_ips)
                      ? (result.metadata.dns as any).resolved_ips.join(", ") || "N/A"
                      : "N/A"}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Findings */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-cyan-400" /> Hallazgos
            </h3>
            {result.findings.length === 0 ? (
              <div className="flex items-center gap-2 text-emerald-400 py-3">
                <CheckCircle className="w-5 h-5" />
                <span className="text-sm">No se detectaron anomalías de red</span>
              </div>
            ) : (
              <div className="space-y-2">
                {result.findings.map((finding, i) => (
                  <div key={i} className={cn("flex items-start gap-2 p-3 rounded-lg border", getRiskBg(String(finding.severity)))}>
                    <AlertTriangle className={cn("w-4 h-4 shrink-0 mt-0.5", getRiskColor(String(finding.severity)))} />
                    <div>
                      <p className={cn("text-xs font-medium capitalize", getRiskColor(String(finding.severity)))}>
                        {String(finding.severity)}
                      </p>
                      <p className="text-xs text-slate-300 mt-0.5">
                        {finding.description || (finding as any).detail || finding.type}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* TLS fingerprint */}
          {result.metadata?.tls_fingerprint && (
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-2 flex items-center gap-2">
                <Fingerprint className="w-4 h-4 text-cyan-400" /> TLS Fingerprint
              </h3>
              <p className="text-[10px] text-mono text-slate-500 break-all">{String(result.metadata.tls_fingerprint)}</p>
            </div>
          )}

          {/* Recommendations */}
          {result.recommendations.length > 0 && (
            <div className="rounded-xl bg-amber-500/5 border border-amber-500/20 p-5">
              <h3 className="text-sm font-semibold text-amber-400 mb-2">Recomendaciones</h3>
              <ul className="space-y-1">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="text-xs text-amber-400/80 flex items-start gap-2">
                    <span>•</span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
