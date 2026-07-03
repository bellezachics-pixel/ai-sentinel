"use client";

import { useState } from "react";
import { Link2, Search, Shield, AlertTriangle, CheckCircle, Loader2, ToggleLeft, ToggleRight, Clock, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg, formatDate } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";
import SecurityReport from "@/components/analysis/SecurityReport";

export default function URLScanner() {
  const [url, setUrl] = useState("");
  const [deepScan, setDeepScan] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<AnalysisResult[]>([]);

  const handleScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.analyzeUrl(url.trim(), deepScan);
      setResult(data);
      setHistory((prev) => [data, ...prev].slice(0, 10));
    } catch {
      setError(
        "No se pudo conectar con el servidor. Verifica que la API esté activa."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white">Escáner de URLs</h2>
        <p className="text-sm text-slate-500 mt-0.5">
          Analiza URLs en busca de phishing, malware y amenazas
        </p>
      </div>

      {/* Input Section */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Link2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              placeholder="https://ejemplo.com/pagina-sospechosa"
              className="w-full h-11 pl-10 pr-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-colors text-mono"
            />
          </div>
          <button
            onClick={handleScan}
            disabled={loading || !url.trim()}
            className="flex items-center justify-center gap-2 px-6 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Search className="w-4 h-4" />
            )}
            {loading ? "Escaneando..." : "Escanear"}
          </button>
        </div>

        {/* Deep scan toggle */}
        <div className="flex items-center gap-2 mt-3">
          <button
            onClick={() => setDeepScan(!deepScan)}
            className="text-slate-400 hover:text-cyan-400 transition-colors"
          >
            {deepScan ? (
              <ToggleRight className="w-8 h-5 text-cyan-400" />
            ) : (
              <ToggleLeft className="w-8 h-5" />
            )}
          </button>
          <span className="text-xs text-slate-400">
            Escaneo profundo (incluye análisis de contenido y red)
          </span>
        </div>
      </div>

      {/* Loading animation */}
      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
            <Shield className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <div className="text-center">
            <p className="text-sm text-slate-300">Analizando URL...</p>
            <p className="text-xs text-slate-500 mt-1">
              Verificando reputación, contenido y certificados
            </p>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-xl bg-red-500/5 border border-red-500/20 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-red-400 font-medium">Error de análisis</p>
            <p className="text-xs text-red-400/70 mt-1">{error}</p>
          </div>
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Risk Score */}
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 flex items-center justify-center">
              <RiskGauge score={result.risk_score.total} size={160} />
            </div>

            {/* Findings */}
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 lg:col-span-2">
              <h3 className="text-sm font-semibold text-slate-300 mb-3">
                Hallazgos
              </h3>
              {result.findings.length === 0 ? (
                <div className="flex items-center gap-2 text-emerald-400 py-4">
                  <CheckCircle className="w-5 h-5" />
                  <span className="text-sm">
                    No se encontraron amenazas significativas
                  </span>
                </div>
              ) : (
                <div className="space-y-2 max-h-[250px] overflow-y-auto">
                  {result.findings.map((finding, i) => (
                    <div
                      key={i}
                      className={cn(
                        "flex items-start gap-3 p-3 rounded-lg border",
                        getRiskBg(finding.severity)
                      )}
                    >
                      <AlertTriangle
                        className={cn(
                          "w-4 h-4 shrink-0 mt-0.5",
                          getRiskColor(finding.severity)
                        )}
                      />
                      <div>
                        <p className="text-xs font-medium text-slate-300">
                          {finding.type}
                        </p>
                        <p className="text-xs text-slate-400 mt-0.5">
                          {finding.description}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Recommendations */}
              {result.recommendations.length > 0 && (
                <div className="mt-4 pt-4 border-t border-[#1e293b]">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Recomendaciones
                  </h4>
                  <ul className="space-y-1.5">
                    {result.recommendations.map((rec, i) => (
                      <li
                        key={i}
                        className="text-xs text-slate-400 flex items-start gap-2"
                      >
                        <span className="text-cyan-400 mt-0.5">•</span>
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
          <SecurityReport result={result} title="Reporte del escaneo de URL" />
        </>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-3">
            Historial de Escaneos
          </h3>
          <div className="space-y-2">
            {history.map((item, i) => (
              <div
                key={item.id || i}
                className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#0a0e1a]/50 hover:bg-[#0a0e1a] transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <ExternalLink className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  <span className="text-xs text-mono text-slate-400 truncate">
                    {item.target}
                  </span>
                </div>
                <div className="flex items-center gap-3 shrink-0 ml-3">
                  <span
                    className={cn(
                      "text-xs font-semibold text-mono px-2 py-0.5 rounded border",
                      getRiskBg(item.risk_score.level),
                      getRiskColor(item.risk_score.level)
                    )}
                  >
                    {item.risk_score.total}
                  </span>
                  <div className="flex items-center gap-1 text-slate-600">
                    <Clock className="w-3 h-3" />
                    <span className="text-[10px] text-mono">
                      {item.timestamp ? formatDate(item.timestamp) : "—"}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
