"use client";

import { useState } from "react";
import {
  Mail,
  User,
  FileText,
  Search,
  Loader2,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";

export default function EmailAnalyzer() {
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!sender.trim() && !subject.trim() && !body.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.analyzeEmail({
        sender: sender.trim(),
        subject: subject.trim(),
        body: body.trim(),
      });
      setResult(data);
    } catch {
      setError(
        "No se pudo conectar con el servidor. Verifica que la API esté activa."
      );
    } finally {
      setLoading(false);
    }
  };

  const socialEngineeringIndicators = result?.findings.filter(
    (f) =>
      f.type.toLowerCase().includes("social") ||
      f.type.toLowerCase().includes("phishing") ||
      f.type.toLowerCase().includes("urgency") ||
      f.type.toLowerCase().includes("impersonation")
  );

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white">Analizador de Email</h2>
        <p className="text-sm text-slate-500 mt-0.5">
          Detecta phishing, ingeniería social y correos maliciosos
        </p>
      </div>

      {/* Input Form */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 space-y-4">
        {/* Sender */}
        <div>
          <label className="text-xs text-slate-400 uppercase tracking-wider mb-1.5 block">
            Remitente
          </label>
          <div className="relative">
            <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="email"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              placeholder="remitente@ejemplo.com"
              className="w-full h-10 pl-10 pr-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-colors text-mono"
            />
          </div>
        </div>

        {/* Subject */}
        <div>
          <label className="text-xs text-slate-400 uppercase tracking-wider mb-1.5 block">
            Asunto
          </label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="Asunto del correo electrónico"
              className="w-full h-10 pl-10 pr-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-colors"
            />
          </div>
        </div>

        {/* Body */}
        <div>
          <label className="text-xs text-slate-400 uppercase tracking-wider mb-1.5 block">
            Cuerpo del mensaje
          </label>
          <div className="relative">
            <FileText className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Pega aquí el contenido del correo electrónico..."
              rows={6}
              className="w-full pl-10 pr-4 py-3 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-colors resize-none"
            />
          </div>
        </div>

        <button
          onClick={handleAnalyze}
          disabled={loading || (!sender.trim() && !subject.trim() && !body.trim())}
          className="flex items-center justify-center gap-2 px-6 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed w-full sm:w-auto"
        >
          {loading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Search className="w-4 h-4" />
          )}
          {loading ? "Analizando..." : "Analizar Email"}
        </button>
      </div>

      {/* Loading */}
      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
            <Mail className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <div className="text-center">
            <p className="text-sm text-slate-300">Analizando correo...</p>
            <p className="text-xs text-slate-500 mt-1">
              Verificando patrones de phishing e ingeniería social
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
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Risk Score */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 flex items-center justify-center">
            <RiskGauge score={result.risk_score.total} size={160} />
          </div>

          {/* Risk Breakdown */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-3">
              Desglose de Riesgo
            </h3>
            <div className="space-y-3">
              {[
                { label: "Contenido", score: result.risk_score.content_score },
                { label: "Cabeceras", score: result.risk_score.header_score },
                { label: "URLs", score: result.risk_score.url_score },
              ].map((item) => (
                <div key={item.label}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-400">{item.label}</span>
                    <span className="text-mono text-slate-300">
                      {item.score}/100
                    </span>
                  </div>
                  <div className="h-1.5 bg-[#1e293b] rounded-full overflow-hidden">
                    <div
                      className={cn(
                        "h-full rounded-full transition-all duration-1000",
                        item.score <= 25
                          ? "bg-emerald-400"
                          : item.score <= 50
                          ? "bg-amber-400"
                          : item.score <= 75
                          ? "bg-orange-500"
                          : "bg-red-500"
                      )}
                      style={{ width: `${item.score}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Social Engineering Indicators */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-3">
              Indicadores de Ingeniería Social
            </h3>
            {socialEngineeringIndicators &&
            socialEngineeringIndicators.length > 0 ? (
              <div className="space-y-2">
                {socialEngineeringIndicators.map((indicator, i) => (
                  <div
                    key={i}
                    className={cn(
                      "flex items-start gap-2 p-2.5 rounded-lg border",
                      getRiskBg(indicator.severity)
                    )}
                  >
                    <AlertTriangle
                      className={cn(
                        "w-3.5 h-3.5 shrink-0 mt-0.5",
                        getRiskColor(indicator.severity)
                      )}
                    />
                    <p className="text-xs text-slate-300">
                      {indicator.description}
                    </p>
                  </div>
                ))}
              </div>
            ) : result.findings.length > 0 ? (
              <div className="space-y-2">
                {result.findings.slice(0, 5).map((finding, i) => (
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
            ) : (
              <div className="flex items-center gap-2 text-emerald-400 py-4">
                <CheckCircle className="w-5 h-5" />
                <span className="text-sm">Sin indicadores sospechosos</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
