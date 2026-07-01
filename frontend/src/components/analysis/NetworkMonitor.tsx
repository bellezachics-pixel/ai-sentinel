"use client";

import { useState } from "react";
import {
  Network,
  Search,
  Loader2,
  AlertTriangle,
  CheckCircle,
  Shield,
  Lock,
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

  const tlsInfo = result?.metadata?.tls as Record<string, unknown> | undefined;
  const arpInfo = result?.metadata?.arp as Record<string, unknown> | undefined;
  const dnsInfo = result?.metadata?.dns as Record<string, unknown> | undefined;

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
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Integrity Score */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 flex flex-col items-center justify-center">
            <RiskGauge score={result.risk_score.total} size={160} />
            <p className="text-xs text-slate-500 mt-3">
              Puntuación de Integridad de Red
            </p>
          </div>

          {/* Status Details */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">
              Estado de la Red
            </h3>
            <div className="space-y-3">
              {/* Connection */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0e1a]/50">
                <div className="flex items-center gap-2.5">
                  <Shield className="w-4 h-4 text-slate-400" />
                  <span className="text-xs text-slate-400">Conexión</span>
                </div>
                <span
                  className={cn(
                    "text-xs font-medium",
                    result.risk_score.level === "low"
                      ? "text-emerald-400"
                      : "text-red-400"
                  )}
                >
                  {result.risk_score.level === "low" ? "Segura" : "Riesgo detectado"}
                </span>
              </div>

              {/* TLS */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0e1a]/50">
                <div className="flex items-center gap-2.5">
                  <Lock className="w-4 h-4 text-slate-400" />
                  <span className="text-xs text-slate-400">TLS/SSL</span>
                </div>
                <span className="text-xs font-medium text-emerald-400">
                  {tlsInfo ? "Verificado" : "N/A"}
                </span>
              </div>

              {/* DNS */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0e1a]/50">
                <div className="flex items-center gap-2.5">
                  <Globe className="w-4 h-4 text-slate-400" />
                  <span className="text-xs text-slate-400">DNS</span>
                </div>
                <span
                  className={cn(
                    "text-xs font-medium",
                    dnsInfo ? "text-amber-400" : "text-emerald-400"
                  )}
                >
                  {dnsInfo ? "Anomalía" : "Normal"}
                </span>
              </div>

              {/* ARP */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0e1a]/50">
                <div className="flex items-center gap-2.5">
                  <Network className="w-4 h-4 text-slate-400" />
                  <span className="text-xs text-slate-400">ARP</span>
                </div>
                <span
                  className={cn(
                    "text-xs font-medium",
                    arpInfo ? "text-red-400" : "text-emerald-400"
                  )}
                >
                  {arpInfo ? "Spoofing detectado" : "Normal"}
                </span>
              </div>
            </div>
          </div>

          {/* TLS Fingerprint & Findings */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-3">
              Hallazgos
            </h3>
            {result.findings.length === 0 ? (
              <div className="flex items-center gap-2 text-emerald-400 py-4">
                <CheckCircle className="w-5 h-5" />
                <span className="text-sm">Red segura</span>
              </div>
            ) : (
              <div className="space-y-2 max-h-[300px] overflow-y-auto">
                {result.findings.map((finding, i) => (
                  <div
                    key={i}
                    className={cn(
                      "flex items-start gap-2 p-2.5 rounded-lg border",
                      getRiskBg(finding.severity)
                    )}
                  >
                    <AlertTriangle
                      className={cn(
                        "w-3.5 h-3.5 shrink-0 mt-0.5",
                        getRiskColor(finding.severity)
                      )}
                    />
                    <p className="text-xs text-slate-300">
                      {finding.description}
                    </p>
                  </div>
                ))}
              </div>
            )}

            {tlsInfo && (
              <div className="mt-4 pt-4 border-t border-[#1e293b]">
                <div className="flex items-center gap-2 mb-2">
                  <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-xs text-slate-400 font-medium">
                    TLS Fingerprint
                  </span>
                </div>
                <p className="text-[10px] text-mono text-slate-500 break-all">
                  {JSON.stringify(tlsInfo).slice(0, 200)}
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
