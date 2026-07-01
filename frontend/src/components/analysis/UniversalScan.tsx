"use client";

import { useState, useRef } from "react";
import {
  Search, Loader2, Shield, AlertTriangle, CheckCircle, Upload,
  Link2, Mail, Phone, FileText, QrCode, Image, Video, Mic, Camera,
} from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";

type InputType = "auto" | "url" | "email" | "phone" | "text" | "file";

function detectInputType(input: string): InputType {
  if (/^https?:\/\//i.test(input) || /^www\./i.test(input)) return "url";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) return "email";
  if (/^[\+]?[\d\s\-\(\)]{7,15}$/.test(input.trim())) return "phone";
  return "text";
}

const TYPE_LABELS: Record<string, string> = {
  url: "URL detectada",
  email: "Correo detectado",
  phone: "Telefono detectado",
  text: "Texto para analizar",
  file: "Archivo para analizar",
};

export default function UniversalScan() {
  const [input, setInput] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [detectedType, setDetectedType] = useState<InputType>("auto");
  const fileRef = useRef<HTMLInputElement>(null);

  const currentType = file ? "file" : detectInputType(input);

  const handleAnalyze = async () => {
    if (!input.trim() && !file) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setDetectedType(currentType);

    try {
      let data: AnalysisResult;
      if (file) {
        const ext = file.name.split(".").pop()?.toLowerCase();
        if (["jpg", "jpeg", "png", "gif", "webp", "bmp"].includes(ext || "")) {
          data = await api.analyzeMedia(file);
        } else {
          data = await api.analyzeMedia(file);
        }
      } else if (currentType === "url") {
        const url = input.startsWith("http") ? input : `https://${input}`;
        data = await api.analyzeUrl(url.trim(), true);
      } else if (currentType === "email") {
        data = await api.analyzeEmail({ sender: input.trim(), subject: "", body: "" });
      } else {
        data = await api.analyzeEmail({ sender: "", subject: "", body: input.trim() });
      }
      setResult(data);
    } catch {
      setError("No se pudo conectar con el servidor. Verifica que la API este activa.");
    } finally {
      setLoading(false);
    }
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) setFile(f);
  };

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div className="text-center">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 mb-4">
          <Search className="w-8 h-8 text-cyan-400" />
        </div>
        <h2 className="text-2xl font-bold text-white">Analizar Cualquier Cosa</h2>
        <p className="text-sm text-slate-500 mt-1">
          Pega una URL, correo, numero, texto o sube un archivo. La IA detecta automaticamente que analizar.
        </p>
      </div>

      {/* Input */}
      <div
        className="rounded-xl bg-[#111827] border border-[#1e293b] p-6"
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleFileDrop}
      >
        <div className="relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
          <input
            type="text"
            value={input}
            onChange={(e) => { setInput(e.target.value); setFile(null); }}
            onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
            placeholder="Pega URL, correo, numero, texto..."
            className="w-full h-14 pl-12 pr-4 rounded-xl bg-[#0a0e1a] border border-[#1e293b] text-base text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-colors"
          />
        </div>

        {/* Type badges */}
        {input.trim() && (
          <div className="flex items-center gap-2 mt-3">
            <span className="text-xs px-2 py-1 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              {TYPE_LABELS[currentType] || "Auto-detectado"}
            </span>
          </div>
        )}

        {/* File upload area */}
        <div className="mt-4 flex flex-wrap gap-2">
          <input ref={fileRef} type="file" className="hidden" onChange={(e) => setFile(e.target.files?.[0] || null)} accept="*/*" />
          <button
            onClick={() => fileRef.current?.click()}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors"
          >
            <Upload className="w-4 h-4" />
            {file ? file.name : "Subir archivo"}
          </button>
        </div>

        {/* Accepted types */}
        <div className="flex flex-wrap gap-2 mt-4">
          {[
            { icon: Link2, label: "URL" },
            { icon: Mail, label: "Correo" },
            { icon: Phone, label: "Telefono" },
            { icon: Image, label: "Imagen" },
            { icon: Video, label: "Video" },
            { icon: Mic, label: "Audio" },
            { icon: FileText, label: "PDF" },
            { icon: QrCode, label: "QR" },
            { icon: Camera, label: "Captura" },
          ].map(({ icon: Icon, label }) => (
            <span key={label} className="flex items-center gap-1 text-[11px] text-slate-600 px-2 py-1 rounded bg-[#0a0e1a]">
              <Icon className="w-3 h-3" />
              {label}
            </span>
          ))}
        </div>

        <button
          onClick={handleAnalyze}
          disabled={loading || (!input.trim() && !file)}
          className="mt-4 flex items-center justify-center gap-2 w-full h-12 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-base font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-cyan-500/20"
        >
          {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Shield className="w-5 h-5" />}
          {loading ? "Analizando..." : "Analizar"}
        </button>
      </div>

      {/* Loading */}
      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <div className="relative w-20 h-20">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
            <Shield className="absolute inset-0 m-auto w-8 h-8 text-cyan-400" />
          </div>
          <p className="text-sm text-slate-300">IA analizando {TYPE_LABELS[detectedType]}...</p>
        </div>
      )}

      {error && (
        <div className="rounded-xl bg-red-500/5 border border-red-500/20 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {result && !loading && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 flex items-center justify-center">
            <RiskGauge score={result.risk_score.total} size={160} />
          </div>
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 lg:col-span-2">
            <h3 className="text-sm font-semibold text-slate-300 mb-3">Hallazgos</h3>
            {result.findings.length === 0 ? (
              <div className="flex items-center gap-2 text-emerald-400 py-4">
                <CheckCircle className="w-5 h-5" />
                <span className="text-sm">No se encontraron amenazas significativas</span>
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
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Recomendaciones</h4>
                <ul className="space-y-1.5">
                  {result.recommendations.map((r, i) => (
                    <li key={i} className="text-xs text-slate-400 flex items-start gap-2">
                      <span className="text-cyan-400 mt-0.5">&#8226;</span>{r}
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
