"use client";

import { useState } from "react";
import {
  MessageSquare, Search, Loader2, AlertTriangle, CheckCircle, Shield,
} from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";
import SecurityReport from "@/components/analysis/SecurityReport";

const PLATFORMS = [
  { id: "whatsapp", label: "WhatsApp", color: "text-emerald-400" },
  { id: "sms", label: "SMS", color: "text-blue-400" },
  { id: "telegram", label: "Telegram", color: "text-sky-400" },
];

export default function MessageAnalyzer() {
  const [platform, setPlatform] = useState("whatsapp");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!message.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.analyzeMessage({ platform, body: message.trim() });
      setResult(data);
    } catch {
      setError("No se pudo conectar con el servidor.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <MessageSquare className="w-6 h-6 text-cyan-400" /> Analizar Mensajes
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">Detecta fraude e ingenieria social en mensajes</p>
      </div>

      {/* Platform selector */}
      <div className="flex gap-2">
        {PLATFORMS.map((p) => (
          <button
            key={p.id}
            onClick={() => setPlatform(p.id)}
            className={cn(
              "flex-1 py-3 rounded-lg border text-sm font-medium transition-all",
              platform === p.id
                ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
                : "bg-[#111827] border-[#1e293b] text-slate-400 hover:border-slate-500"
            )}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Message input */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
        <label className="text-xs text-slate-400 uppercase tracking-wider mb-2 block">
          Pega el mensaje sospechoso
        </label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder={`Pega aqui el mensaje de ${PLATFORMS.find((p) => p.id === platform)?.label}...`}
          rows={6}
          className="w-full px-4 py-3 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 resize-none"
        />
        <button
          onClick={handleAnalyze}
          disabled={loading || !message.trim()}
          className="mt-3 flex items-center justify-center gap-2 px-6 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 w-full sm:w-auto"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          {loading ? "Analizando..." : "Analizar Mensaje"}
        </button>
      </div>

      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
            <Shield className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <p className="text-sm text-slate-300">Analizando mensaje por patrones de fraude...</p>
        </div>
      )}

      {error && (
        <div className="rounded-xl bg-red-500/5 border border-red-500/20 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {result && !loading && (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 flex items-center justify-center">
              <RiskGauge score={result.risk_score.total} size={160} />
            </div>
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 lg:col-span-2">
              <h3 className="text-sm font-semibold text-slate-300 mb-3">Resultados</h3>
              {result.findings.length === 0 ? (
                <div className="flex items-center gap-2 text-emerald-400 py-4">
                  <CheckCircle className="w-5 h-5" />
                  <span className="text-sm">El mensaje parece seguro</span>
                </div>
              ) : (
                <div className="space-y-2 max-h-[300px] overflow-y-auto">
                  {result.findings.map((f, i) => (
                    <div key={i} className={cn("flex items-start gap-3 p-3 rounded-lg border", getRiskBg(f.severity))}>
                      <AlertTriangle className={cn("w-4 h-4 shrink-0 mt-0.5", getRiskColor(f.severity))} />
                      <div>
                        <p className="text-xs font-medium text-slate-300">{f.type}</p>
                        <p className="text-xs text-slate-400 mt-0.5">{f.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {result.recommendations.length > 0 && (
                <div className="mt-4 pt-4 border-t border-[#1e293b]">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase mb-2">Recomendaciones</h4>
                  <ul className="space-y-1.5">
                    {result.recommendations.map((r, i) => (
                      <li key={i} className="text-xs text-slate-400 flex items-start gap-2">
                        <span className="text-cyan-400">&#8226;</span>{r}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
          <SecurityReport result={result} title="Reporte del mensaje analizado" />
        </>
      )}
    </div>
  );
}
