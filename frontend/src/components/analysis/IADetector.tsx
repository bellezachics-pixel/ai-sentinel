"use client";

import { useState, useRef } from "react";
import {
  Bot, Video, Image, Mic, Upload, Loader2, AlertTriangle, CheckCircle, Shield,
} from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";

const MEDIA_TYPES = [
  { id: "video", label: "Video IA", icon: Video, accept: "video/*", desc: "Detectar videos hechos con IA" },
  { id: "image", label: "Imagen IA", icon: Image, accept: "image/*", desc: "Detectar imagenes generadas con IA" },
  { id: "audio", label: "Voz clonada", icon: Mic, accept: "audio/*", desc: "Detectar voces clonadas con IA" },
];

export default function IADetector() {
  const [selected, setSelected] = useState(0);
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleAnalyze = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.analyzeMedia(file);
      setResult(data);
    } catch {
      setError("No se pudo analizar el archivo.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Bot className="w-6 h-6 text-cyan-400" /> Detector de IA
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">Detecta contenido generado por inteligencia artificial</p>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {MEDIA_TYPES.map((mt, i) => (
          <button
            key={mt.id}
            onClick={() => { setSelected(i); setFile(null); setResult(null); }}
            className={cn(
              "flex flex-col items-center gap-3 p-5 rounded-xl border transition-all",
              selected === i
                ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
                : "bg-[#111827] border-[#1e293b] text-slate-400 hover:border-slate-500"
            )}
          >
            <mt.icon className="w-8 h-8" />
            <span className="text-sm font-medium">{mt.label}</span>
            <span className="text-xs text-slate-500 text-center">{mt.desc}</span>
          </button>
        ))}
      </div>

      <div
        className="rounded-xl bg-[#111827] border-2 border-dashed border-[#1e293b] p-8 text-center hover:border-cyan-500/30 transition-colors cursor-pointer"
        onClick={() => fileRef.current?.click()}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => { e.preventDefault(); setFile(e.dataTransfer.files[0] || null); }}
      >
        <input ref={fileRef} type="file" className="hidden" accept={MEDIA_TYPES[selected].accept} onChange={(e) => setFile(e.target.files?.[0] || null)} />
        <Upload className="w-10 h-10 text-slate-500 mx-auto mb-3" />
        {file ? (
          <p className="text-sm text-slate-300">{file.name}</p>
        ) : (
          <p className="text-sm text-slate-400">Sube un {MEDIA_TYPES[selected].label.toLowerCase()} para analizar</p>
        )}
      </div>

      {file && (
        <button
          onClick={handleAnalyze}
          disabled={loading}
          className="flex items-center justify-center gap-2 w-full h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium disabled:opacity-50"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
          {loading ? "Analizando..." : "Detectar IA"}
        </button>
      )}

      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
            <Bot className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <p className="text-sm text-slate-300">Analizando autenticidad del contenido...</p>
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
            <h3 className="text-sm font-semibold text-slate-300 mb-3">Analisis de Autenticidad</h3>
            {result.findings.length === 0 ? (
              <div className="flex items-center gap-2 text-emerald-400 py-4">
                <CheckCircle className="w-5 h-5" />
                <span className="text-sm">El contenido parece autentico (no generado por IA)</span>
              </div>
            ) : (
              <div className="space-y-2">
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
      )}
    </div>
  );
}
