"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import {
  Search,
  Loader2,
  AlertTriangle,
  CheckCircle,
  Globe,
  Hash,
  Server,
  Link2,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { api } from "@/lib/api";
import type { ThreatIntelResult } from "@/lib/api";
import { cn } from "@/lib/utils";

const LazyBarChart = dynamic(
  () => import("recharts").then((m) => ({ default: m.BarChart })),
  { ssr: false }
);
const LazyBar = dynamic(
  () => import("recharts").then((m) => ({ default: m.Bar })),
  { ssr: false }
);
const LazyXAxis = dynamic(
  () => import("recharts").then((m) => ({ default: m.XAxis })),
  { ssr: false }
);
const LazyYAxis = dynamic(
  () => import("recharts").then((m) => ({ default: m.YAxis })),
  { ssr: false }
);
const LazyTooltip = dynamic(
  () => import("recharts").then((m) => ({ default: m.Tooltip })),
  { ssr: false }
);
const LazyResponsiveContainer = dynamic(
  () => import("recharts").then((m) => ({ default: m.ResponsiveContainer })),
  { ssr: false }
);
const LazyCartesianGrid = dynamic(
  () => import("recharts").then((m) => ({ default: m.CartesianGrid })),
  { ssr: false }
);
const LazyCell = dynamic(
  () => import("recharts").then((m) => ({ default: m.Cell })),
  { ssr: false }
);

type IndicatorType = "url" | "ip" | "domain" | "hash";

const INDICATOR_TYPES: { id: IndicatorType; label: string; icon: React.ElementType }[] = [
  { id: "url", label: "URL", icon: Link2 },
  { id: "ip", label: "IP", icon: Server },
  { id: "domain", label: "Dominio", icon: Globe },
  { id: "hash", label: "Hash", icon: Hash },
];

export default function ThreatIntel() {
  const [indicator, setIndicator] = useState("");
  const [indicatorType, setIndicatorType] = useState<IndicatorType>("url");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<ThreatIntelResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleLookup = async () => {
    if (!indicator.trim()) return;
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const data = await api.threatIntelLookup(indicator.trim(), indicatorType);
      setResults(data.results);
    } catch {
      setError(
        "No se pudo consultar la inteligencia de amenazas. Verifica que la API esté activa."
      );
    } finally {
      setLoading(false);
    }
  };

  const chartData = results?.map((r) => ({
    name: r.source,
    score: r.score,
    fill: r.is_malicious ? "#ef4444" : "#34d399",
  }));

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white">
          Inteligencia de Amenazas
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">
          Consulta múltiples fuentes de inteligencia sobre indicadores de
          compromiso
        </p>
      </div>

      {/* Input */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 space-y-4">
        {/* Type selector */}
        <div className="flex gap-2">
          {INDICATOR_TYPES.map((type) => {
            const Icon = type.icon;
            return (
              <button
                key={type.id}
                onClick={() => setIndicatorType(type.id)}
                className={cn(
                  "flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all border",
                  indicatorType === type.id
                    ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
                    : "text-slate-400 border-transparent hover:bg-white/5 hover:text-slate-300"
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                {type.label}
              </button>
            );
          })}
        </div>

        {/* Input + Button */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleLookup()}
              placeholder={
                indicatorType === "url"
                  ? "https://ejemplo.com"
                  : indicatorType === "ip"
                  ? "192.168.1.1"
                  : indicatorType === "domain"
                  ? "ejemplo.com"
                  : "sha256hash..."
              }
              className="w-full h-11 pl-10 pr-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-colors text-mono"
            />
          </div>
          <button
            onClick={handleLookup}
            disabled={loading || !indicator.trim()}
            className="flex items-center justify-center gap-2 px-6 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Search className="w-4 h-4" />
            )}
            {loading ? "Consultando..." : "Consultar"}
          </button>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
            <Search className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <div className="text-center">
            <p className="text-sm text-slate-300">
              Consultando fuentes de inteligencia...
            </p>
            <p className="text-xs text-slate-500 mt-1">
              VirusTotal, Urlscan.io, AbuseIPDB
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
      {results && !loading && (
        <div className="space-y-4">
          {/* Score Comparison Chart */}
          {chartData && chartData.length > 0 && (
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4">
                Comparación de Puntuaciones
              </h3>
              <div className="h-[200px]">
                <LazyResponsiveContainer width="100%" height="100%">
                  <LazyBarChart data={chartData}>
                    <LazyCartesianGrid
                      strokeDasharray="3 3"
                      stroke="#1e293b"
                    />
                    <LazyXAxis
                      dataKey="name"
                      tick={{ fill: "#94a3b8", fontSize: 11 }}
                      axisLine={{ stroke: "#1e293b" }}
                      tickLine={false}
                    />
                    <LazyYAxis
                      domain={[0, 100]}
                      tick={{ fill: "#94a3b8", fontSize: 11 }}
                      axisLine={{ stroke: "#1e293b" }}
                      tickLine={false}
                    />
                    <LazyTooltip
                      contentStyle={{
                        backgroundColor: "#1e293b",
                        border: "1px solid #334155",
                        borderRadius: "8px",
                        color: "#e2e8f0",
                        fontSize: "12px",
                      }}
                    />
                    <LazyBar dataKey="score" radius={[4, 4, 0, 0]}>
                      {chartData.map((entry, index) => (
                        <LazyCell
                          key={`cell-${index}`}
                          fill={entry.fill}
                        />
                      ))}
                    </LazyBar>
                  </LazyBarChart>
                </LazyResponsiveContainer>
              </div>
            </div>
          )}

          {/* Source Results */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {results.map((result, i) => (
              <div
                key={i}
                className={cn(
                  "rounded-xl bg-[#111827] border p-5 transition-all",
                  result.is_malicious
                    ? "border-red-500/30"
                    : "border-emerald-500/20"
                )}
              >
                <div className="flex items-center justify-between mb-4">
                  <h4 className="text-sm font-semibold text-slate-300">
                    {result.source}
                  </h4>
                  {result.is_malicious ? (
                    <ShieldX className="w-5 h-5 text-red-400" />
                  ) : (
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  )}
                </div>

                {/* Score */}
                <div className="mb-3">
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-400">Puntuación</span>
                    <span
                      className={cn(
                        "text-mono font-bold",
                        result.is_malicious
                          ? "text-red-400"
                          : "text-emerald-400"
                      )}
                    >
                      {result.score}/100
                    </span>
                  </div>
                  <div className="h-1.5 bg-[#1e293b] rounded-full overflow-hidden">
                    <div
                      className={cn(
                        "h-full rounded-full transition-all duration-1000",
                        result.is_malicious ? "bg-red-500" : "bg-emerald-400"
                      )}
                      style={{ width: `${result.score}%` }}
                    />
                  </div>
                </div>

                {/* Verdict */}
                <div
                  className={cn(
                    "flex items-center gap-2 px-3 py-2 rounded-lg",
                    result.is_malicious
                      ? "bg-red-500/10"
                      : "bg-emerald-500/10"
                  )}
                >
                  {result.is_malicious ? (
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                  ) : (
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                  )}
                  <span
                    className={cn(
                      "text-xs font-medium",
                      result.is_malicious
                        ? "text-red-400"
                        : "text-emerald-400"
                    )}
                  >
                    {result.is_malicious ? "Malicioso" : "Limpio"}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {results.length === 0 && (
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-3">
              <CheckCircle className="w-8 h-8 text-emerald-400" />
              <p className="text-sm text-slate-300">
                No se encontraron reportes maliciosos
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
