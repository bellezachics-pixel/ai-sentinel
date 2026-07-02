"use client";

import { useState } from "react";
import {
  Globe, Shield, ShoppingCart, Plane, Building2, Link2,
  Search, Loader2, AlertTriangle, CheckCircle, CreditCard,
} from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";

const QUICK_CHECKS = [
  { icon: Globe, label: "Pagina web segura", placeholder: "https://ejemplo.com" },
  { icon: CreditCard, label: "Tienda en linea", placeholder: "https://tienda.com" },
  { icon: Plane, label: "Agencia de viajes", placeholder: "https://viajes.com" },
  { icon: ShoppingCart, label: "Sitio de compras", placeholder: "https://shop.com" },
  { icon: Building2, label: "Pagina bancaria", placeholder: "https://mibanco.com" },
  { icon: Link2, label: "Analizar enlace", placeholder: "https://enlace-sospechoso.com" },
];

export default function InternetAnalyzer() {
  const [url, setUrl] = useState("");
  const [selectedCheck, setSelectedCheck] = useState(0);
  const [deepScan] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const target = url.startsWith("http") ? url.trim() : `https://${url.trim()}`;
      const data = await api.analyzeUrl(target, deepScan);
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
          <Globe className="w-6 h-6 text-cyan-400" /> Internet
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">Verifica la seguridad de paginas web, tiendas y servicios en linea</p>
      </div>

      {/* Quick check buttons */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
        {QUICK_CHECKS.map((check, i) => (
          <button
            key={i}
            onClick={() => { setSelectedCheck(i); setUrl(""); }}
            className={cn(
              "flex items-center gap-2 p-3 rounded-lg border text-sm transition-all",
              selectedCheck === i
                ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
                : "bg-[#111827] border-[#1e293b] text-slate-400 hover:border-slate-500"
            )}
          >
            <check.icon className="w-4 h-4 shrink-0" />
            <span className="truncate">{check.label}</span>
          </button>
        ))}
      </div>

      {/* URL Input */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
        <label className="text-xs text-slate-400 uppercase tracking-wider mb-2 block">
          {QUICK_CHECKS[selectedCheck].label}
        </label>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              placeholder={QUICK_CHECKS[selectedCheck].placeholder}
              className="w-full h-11 pl-10 pr-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-colors"
            />
          </div>
          <button
            onClick={handleScan}
            disabled={loading || !url.trim()}
            className="flex items-center justify-center gap-2 px-6 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 shrink-0"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {loading ? "Verificando..." : "Verificar"}
          </button>
        </div>
      </div>

      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
            <Shield className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <p className="text-sm text-slate-300">Verificando seguridad del sitio...</p>
          <div className="flex flex-wrap justify-center gap-2 text-xs text-slate-500">
            <span>Certificado SSL</span><span>&#8226;</span>
            <span>Reputacion</span><span>&#8226;</span>
            <span>Contenido</span><span>&#8226;</span>
            <span>Headers</span>
          </div>
        </div>
      )}

      {error && (
        <div className="rounded-xl bg-red-500/5 border border-red-500/20 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {result && !loading && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 flex items-center justify-center">
            <RiskGauge score={result.risk_score.total} size={160} />
          </div>
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 lg:col-span-2">
            <h3 className="text-sm font-semibold text-slate-300 mb-3">Resultados del Analisis</h3>
            {result.findings.length === 0 ? (
              <div className="flex items-center gap-2 text-emerald-400 py-4">
                <CheckCircle className="w-5 h-5" />
                <span className="text-sm">Este sitio parece seguro</span>
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
      )}
    </div>
  );
}
