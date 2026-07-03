"use client";

import { useState, useRef } from "react";
import {
  FolderOpen, FileText, File, Archive, Smartphone, Monitor,
  Image, Upload, Loader2, AlertTriangle, CheckCircle, Shield,
} from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";
import SecurityReport from "@/components/analysis/SecurityReport";

const FILE_TYPES = [
  { ext: "pdf", label: "PDF", icon: FileText, accept: ".pdf" },
  { ext: "docx", label: "Word", icon: File, accept: ".doc,.docx" },
  { ext: "zip", label: "ZIP", icon: Archive, accept: ".zip,.rar,.7z" },
  { ext: "apk", label: "APK Android", icon: Smartphone, accept: ".apk" },
  { ext: "exe", label: "Ejecutable", icon: Monitor, accept: ".exe,.msi,.dmg" },
  { ext: "img", label: "Imagen", icon: Image, accept: "image/*" },
];

export default function FileAnalyzer() {
  const [file, setFile] = useState<File | null>(null);
  const [selectedType, setSelectedType] = useState(0);
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
      const data = await api.analyzeFile(file);
      setResult(data);
    } catch {
      setError("No se pudo analizar el archivo.");
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) setFile(f);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const fileMeta = result?.metadata as
    | {
        sha256?: string;
        size_bytes?: number;
        extension?: string;
        virustotal_available?: boolean;
      }
    | undefined;

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <FolderOpen className="w-6 h-6 text-cyan-400" /> Analizar Archivos
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">Analiza archivos en busca de malware y contenido sospechoso</p>
      </div>

      {/* File type selector */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
        {FILE_TYPES.map((ft, i) => (
          <button
            key={ft.ext}
            onClick={() => { setSelectedType(i); setFile(null); setResult(null); }}
            className={cn(
              "flex flex-col items-center gap-2 p-3 rounded-lg border text-xs transition-all",
              selectedType === i
                ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
                : "bg-[#111827] border-[#1e293b] text-slate-400 hover:border-slate-500"
            )}
          >
            <ft.icon className="w-5 h-5" />
            {ft.label}
          </button>
        ))}
      </div>

      {/* Upload area */}
      <div
        className="rounded-xl bg-[#111827] border-2 border-dashed border-[#1e293b] p-8 text-center hover:border-cyan-500/30 transition-colors cursor-pointer"
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        onClick={() => fileRef.current?.click()}
      >
        <input ref={fileRef} type="file" className="hidden" accept={FILE_TYPES[selectedType].accept} onChange={(e) => setFile(e.target.files?.[0] || null)} />
        <Upload className="w-10 h-10 text-slate-500 mx-auto mb-3" />
        {file ? (
          <div>
            <p className="text-sm text-slate-300 font-medium">{file.name}</p>
            <p className="text-xs text-slate-500 mt-1">{formatFileSize(file.size)}</p>
          </div>
        ) : (
          <div>
            <p className="text-sm text-slate-400">Arrastra un archivo aqui o haz clic para seleccionar</p>
            <p className="text-xs text-slate-600 mt-1">Formatos: {FILE_TYPES[selectedType].accept}</p>
          </div>
        )}
      </div>

      {file && (
        <button
          onClick={handleAnalyze}
          disabled={loading}
          className="flex items-center justify-center gap-2 w-full h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
          {loading ? "Analizando..." : "Analizar Archivo"}
        </button>
      )}

      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
            <Shield className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <p className="text-sm text-slate-300">Escaneando archivo por malware...</p>
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
              {fileMeta && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-4">
                  <div className="rounded-lg bg-[#0a0e1a]/50 p-3">
                    <p className="text-[10px] uppercase text-slate-500 mb-1">SHA-256</p>
                    <p className="text-xs text-slate-300 font-mono break-all">{fileMeta.sha256 || "N/A"}</p>
                  </div>
                  <div className="rounded-lg bg-[#0a0e1a]/50 p-3">
                    <p className="text-[10px] uppercase text-slate-500 mb-1">Reputacion</p>
                    <p className="text-xs text-slate-300">
                      VirusTotal {fileMeta.virustotal_available ? "consultado" : "no configurado"}
                    </p>
                    <p className="text-xs text-slate-500 mt-1">
                      {typeof fileMeta.size_bytes === "number" ? formatFileSize(fileMeta.size_bytes) : "N/A"}
                      {fileMeta.extension ? ` · .${fileMeta.extension}` : ""}
                    </p>
                  </div>
                </div>
              )}
              {result.findings.length === 0 ? (
                <div className="flex items-center gap-2 text-emerald-400 py-4">
                  <CheckCircle className="w-5 h-5" />
                  <span className="text-sm">El archivo parece seguro</span>
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
          <SecurityReport result={result} title="Reporte del archivo analizado" />
        </>
      )}
    </div>
  );
}
