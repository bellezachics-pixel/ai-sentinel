"use client";

import { useState } from "react";
import {
  Fingerprint, Mail, Phone, User, Key, Search, Loader2,
  CheckCircle, Shield, ShieldAlert, AlertTriangle,
} from "lucide-react";
import { api, type AnalysisResult } from "@/lib/api";
import { cn } from "@/lib/utils";

interface BreachInfo {
  name: string;
  date: string;
  data: string[] | string;
}

const CHECKS = [
  { id: "email", label: "Correo filtrado", icon: Mail, placeholder: "tu@correo.com", description: "Busca si tu correo aparecio en filtraciones de datos" },
  { id: "phone", label: "Telefono filtrado", icon: Phone, placeholder: "+52 555 123 4567", description: "Busca si tu numero aparece en filtraciones o reportes de spam" },
  { id: "username", label: "Usuario comprometido", icon: User, placeholder: "tu_usuario", description: "Busca si tu nombre de usuario fue comprometido" },
  { id: "password", label: "Password comprometida", icon: Key, placeholder: "tu_password", description: "Verifica si una contrasena fue expuesta (no se almacena)" },
];

export default function IdentityCheck() {
  const [selectedCheck, setSelectedCheck] = useState(0);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleCheck = async () => {
    if (!input.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const checkType = CHECKS[selectedCheck].id;
      const data = await api.checkIdentity(input.trim(), checkType);
      setResult(data);
    } catch {
      setError("No se pudo verificar. Verifica que la API este activa.");
    } finally {
      setLoading(false);
    }
  };

  const resultMeta = result?.metadata as { breaches?: BreachInfo[] } | undefined;
  const breaches = resultMeta?.breaches || [];
  const found = result?.findings.some((f) => f.type === "breach_found");
  const apiError = result?.findings.some((f) => f.type === "identity_check_error");

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Fingerprint className="w-6 h-6 text-cyan-400" /> Identidad Digital
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">Verifica si tus datos han sido comprometidos</p>
      </div>

      {/* Check type selector */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {CHECKS.map((check, i) => (
          <button
            key={check.id}
            onClick={() => { setSelectedCheck(i); setInput(""); setResult(null); setError(null); }}
            className={cn(
              "flex flex-col items-center gap-2 p-4 rounded-lg border text-sm transition-all",
              selectedCheck === i
                ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
                : "bg-[#111827] border-[#1e293b] text-slate-400 hover:border-slate-500"
            )}
          >
            <check.icon className="w-5 h-5" />
            <span className="text-xs text-center">{check.label}</span>
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
        <label className="text-xs text-slate-400 uppercase tracking-wider mb-2 block">
          {CHECKS[selectedCheck].description}
        </label>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type={CHECKS[selectedCheck].id === "password" ? "password" : "text"}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleCheck()}
            placeholder={CHECKS[selectedCheck].placeholder}
            className="flex-1 h-11 px-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20"
          />
          <button
            onClick={handleCheck}
            disabled={loading || !input.trim()}
            className="flex items-center justify-center gap-2 px-6 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 shrink-0"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {loading ? "Buscando..." : "Verificar"}
          </button>
        </div>
        {CHECKS[selectedCheck].id === "password" && (
          <p className="text-xs text-slate-600 mt-2 flex items-center gap-1">
            <Shield className="w-3 h-3" />
            Tu contrasena se verifica mediante hash y nunca se almacena ni transmite en texto plano
          </p>
        )}
      </div>

      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <Loader2 className="w-10 h-10 text-cyan-400 animate-spin" />
          <p className="text-sm text-slate-300">Buscando en bases de datos de filtraciones...</p>
        </div>
      )}

      {error && !loading && (
        <div className="rounded-xl bg-red-500/5 border border-red-500/20 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-red-400 font-medium">Error</p>
            <p className="text-xs text-red-400/70 mt-1">{error}</p>
          </div>
        </div>
      )}

      {result && !loading && (
        <div className={cn(
          "rounded-xl border p-6",
          found ? "bg-red-500/5 border-red-500/20" : apiError ? "bg-amber-500/5 border-amber-500/20" : "bg-emerald-500/5 border-emerald-500/20"
        )}>
          <div className="flex items-center gap-3 mb-4">
            {found ? (
              <>
                <ShieldAlert className="w-8 h-8 text-red-400" />
                <div>
                  <p className="text-lg font-bold text-red-400">Datos comprometidos</p>
                  <p className="text-sm text-red-400/70">Se encontraron {breaches.length} filtracion(es)</p>
                </div>
              </>
            ) : apiError ? (
              <>
                <AlertTriangle className="w-8 h-8 text-amber-400" />
                <div>
                  <p className="text-lg font-bold text-amber-400">No se pudo verificar</p>
                  <p className="text-sm text-amber-400/70">
                    {result.findings.find((f) => f.type === "identity_check_error")?.description || "Error desconocido"}
                  </p>
                </div>
              </>
            ) : (
              <>
                <CheckCircle className="w-8 h-8 text-emerald-400" />
                <div>
                  <p className="text-lg font-bold text-emerald-400">No se encontraron filtraciones</p>
                  <p className="text-sm text-emerald-400/70">Tus datos no aparecen en bases de datos conocidas</p>
                </div>
              </>
            )}
          </div>

          {found && (
            <div className="space-y-3 mt-4">
              {breaches.map((breach, i) => (
                <div key={i} className="bg-[#111827] rounded-lg p-4 border border-red-500/10">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-semibold text-slate-200">{breach.name}</span>
                    <span className="text-xs text-slate-500">{breach.date}</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Datos expuestos: {Array.isArray(breach.data) ? breach.data.join(", ") : breach.data}
                  </p>
                </div>
              ))}
            </div>
          )}

          {result.recommendations.length > 0 && (
            <div className={cn(
              "rounded-lg p-4 mt-4",
              found ? "bg-amber-500/10 border border-amber-500/20" : "bg-[#111827] border border-[#1e293b]"
            )}>
              <h4 className={cn("text-sm font-semibold mb-2", found ? "text-amber-400" : "text-slate-300")}>Recomendaciones</h4>
              <ul className="space-y-1 text-xs text-slate-400">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2">
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
