"use client";

import { useState } from "react";
import {
  Crown, CreditCard, ShoppingBag, Ticket, Building, Package,
  TrendingUp, Phone, ShieldCheck, Wifi, Loader2, AlertTriangle,
  CheckCircle, Shield, Lock,
} from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";
import SecurityReport from "@/components/analysis/SecurityReport";

const PREMIUM_FEATURES = [
  { id: "payments", label: "Pagos seguros", icon: CreditCard, desc: "Verificar si un sitio acepta pagos seguros", placeholder: "https://tienda.com" },
  { id: "fake-store", label: "Tiendas falsas", icon: ShoppingBag, desc: "Detectar tiendas falsas", placeholder: "https://tienda-sospechosa.com" },
  { id: "tickets", label: "Boletos falsos", icon: Ticket, desc: "Detectar paginas falsas de boletos", placeholder: "https://boletos.com" },
  { id: "hotels", label: "Hoteles/Viajes", icon: Building, desc: "Verificar hoteles y agencias", placeholder: "https://hotel.com" },
  { id: "marketplace", label: "Marketplace", icon: Package, desc: "Verificar vendedores de Marketplace", placeholder: "https://marketplace.com/vendedor" },
  { id: "investment", label: "Inversiones", icon: TrendingUp, desc: "Analizar promesas de ganancias irreales", placeholder: "https://inversion.com" },
  { id: "phone-fraud", label: "Fraude telefonico", icon: Phone, desc: "Verificar numeros con reportes de fraude", placeholder: "+52 555 123 4567" },
  { id: "full-audit", label: "Auditoria completa", icon: ShieldCheck, desc: "Revision completa de seguridad digital", placeholder: "" },
  { id: "connection", label: "Mi conexion es segura?", icon: Wifi, desc: "Detectar MITM, DNS Spoofing, SSL Stripping, Evil Twin", placeholder: "" },
];

export default function PremiumFeatures() {
  const [selected, setSelected] = useState(0);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const feature = PREMIUM_FEATURES[selected];

  const handleAnalyze = async () => {
    if (feature.id === "connection" || feature.id === "full-audit") {
      await runConnectionAudit();
      return;
    }
    if (!input.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      if (feature.id === "phone-fraud") {
        const data = await api.analyzeEmail({ sender: input.trim(), subject: "phone-check", body: `Verificar numero: ${input}` });
        setResult(data);
      } else {
        const url = input.startsWith("http") ? input.trim() : `https://${input.trim()}`;
        const data = await api.analyzeUrl(url, true);
        setResult(data);
      }
    } catch {
      setError("No se pudo conectar con el servidor.");
    } finally {
      setLoading(false);
    }
  };

  const runConnectionAudit = async () => {
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const data = await api.checkNetwork();
      setResult(data);
    } catch {
      setError("No se pudo verificar la conexion con el servidor.");
    } finally {
      setLoading(false);
    }
  };

  const needsInput = feature.placeholder !== "";

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Crown className="w-6 h-6 text-amber-400" /> Funciones Premium
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">Herramientas avanzadas de ciberseguridad</p>
      </div>

      {/* Feature grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
        {PREMIUM_FEATURES.map((f, i) => (
          <button
            key={f.id}
            onClick={() => { setSelected(i); setInput(""); setResult(null); }}
            className={cn(
              "flex items-start gap-2 p-3 rounded-lg border text-left transition-all",
              selected === i
                ? "bg-amber-500/10 border-amber-500/30 text-amber-400"
                : "bg-[#111827] border-[#1e293b] text-slate-400 hover:border-slate-500"
            )}
          >
            <f.icon className="w-4 h-4 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-medium">{f.label}</p>
              <p className="text-[10px] text-slate-500 mt-0.5">{f.desc}</p>
            </div>
          </button>
        ))}
      </div>

      {/* Input / action */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
        <h3 className="text-sm font-semibold text-slate-300 mb-3">{feature.label}</h3>
        <p className="text-xs text-slate-500 mb-3">{feature.desc}</p>
        {needsInput && (
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
            placeholder={feature.placeholder}
            className="w-full h-11 px-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/20 mb-3"
          />
        )}
        <button
          onClick={handleAnalyze}
          disabled={loading || (needsInput && !input.trim())}
          className="flex items-center justify-center gap-2 w-full h-11 rounded-lg bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white text-sm font-medium disabled:opacity-50"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
          {loading ? "Analizando..." : feature.id === "connection" ? "Verificar Conexion" : feature.id === "full-audit" ? "Iniciar Auditoria" : "Analizar"}
        </button>
      </div>

      {error && (
        <div className="rounded-xl bg-red-500/5 border border-red-500/20 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {result && !loading && (
        <div className="space-y-4">
          {(feature.id === "connection" || feature.id === "full-audit") && (
            <div className="rounded-xl bg-cyan-500/5 border border-cyan-500/20 p-4 flex items-start gap-3">
              <Lock className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-cyan-300">
                  Analisis real de red
                </p>
                <p className="text-xs text-slate-400 mt-1">
                  Este resultado viene del backend. Desde una web no se puede
                  inspeccionar tabla ARP, redes cercanas ni configuracion
                  interna del modem, pero si se revisan senales de conectividad,
                  DNS/TLS y anomalias disponibles para la app.
                </p>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 flex items-center justify-center">
              <RiskGauge score={result.risk_score.total} size={160} />
            </div>
            <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 lg:col-span-2">
              <h3 className="text-sm font-semibold text-slate-300 mb-3">Resultados</h3>
              {result.findings.length === 0 ? (
                <div className="flex items-center gap-2 text-emerald-400 py-4">
                  <CheckCircle className="w-5 h-5" />
                  <span className="text-sm">No se encontraron problemas</span>
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
            </div>
          </div>
          <SecurityReport result={result} title={`Reporte premium - ${feature.label}`} />
        </div>
      )}
    </div>
  );
}
