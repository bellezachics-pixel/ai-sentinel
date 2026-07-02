"use client";

import { useState, useRef, useCallback } from "react";
import Image from "next/image";
import {
  ScanEye,
  Loader2,
  AlertTriangle,
  CheckCircle,
  X,
  FileVideo,
  FileAudio,
  Image as ImageIcon,
  Percent,
} from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";

export default function DeepfakeDetector() {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const getFileIcon = (type: string) => {
    if (type.startsWith("video/")) return FileVideo;
    if (type.startsWith("audio/")) return FileAudio;
    return ImageIcon;
  };

  const handleFile = useCallback((f: File) => {
    setFile(f);
    setResult(null);
    setError(null);
    if (f.type.startsWith("image/")) {
      const reader = new FileReader();
      reader.onload = (e) => setPreview(e.target?.result as string);
      reader.readAsDataURL(f);
    } else {
      setPreview(null);
    }
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const f = e.dataTransfer.files[0];
      if (f) handleFile(f);
    },
    [handleFile]
  );

  const handleAnalyze = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.analyzeMedia(file);
      setResult(data);
    } catch {
      setError(
        "No se pudo analizar el archivo. Verifica que la API esté activa."
      );
    } finally {
      setLoading(false);
    }
  };

  const clearFile = () => {
    setFile(null);
    setPreview(null);
    setResult(null);
    setError(null);
  };

  const confidenceScore = result?.metadata?.confidence as number | undefined;
  const manipulationIndicators = result?.findings.filter(
    (f) =>
      f.type.toLowerCase().includes("manipulation") ||
      f.type.toLowerCase().includes("deepfake") ||
      f.type.toLowerCase().includes("synthetic") ||
      f.type.toLowerCase().includes("artifact")
  );

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white">Detector de Deepfakes</h2>
        <p className="text-sm text-slate-500 mt-0.5">
          Analiza imágenes, audio y video para detectar manipulaciones con IA
        </p>
      </div>

      {/* Upload Zone */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
        {!file ? (
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={cn(
              "border-2 border-dashed rounded-xl p-12 flex flex-col items-center gap-4 cursor-pointer transition-all",
              dragOver
                ? "border-cyan-400 bg-cyan-500/5"
                : "border-[#1e293b] hover:border-[#334155] hover:bg-white/[0.01]"
            )}
          >
            <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 flex items-center justify-center">
              <ScanEye className="w-7 h-7 text-cyan-400" />
            </div>
            <div className="text-center">
              <p className="text-sm text-slate-300">
                Arrastra un archivo aquí o{" "}
                <span className="text-cyan-400">haz clic para seleccionar</span>
              </p>
              <p className="text-xs text-slate-500 mt-1">
                Imágenes (PNG, JPG), Audio (MP3, WAV), Video (MP4, WEBM)
              </p>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*,audio/*,video/*"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFile(f);
              }}
              className="hidden"
            />
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-start gap-4">
              {/* Preview */}
              {preview ? (
                <div className="relative">
                  <div className="rounded-lg overflow-hidden border border-[#1e293b] bg-[#0a0e1a]">
                    <Image
                      src={preview}
                      alt="Preview"
                      width={200}
                      height={200}
                      unoptimized
                      className="max-w-[200px] max-h-[200px] object-contain"
                    />
                  </div>
                  <button
                    onClick={clearFile}
                    className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-red-500/80 hover:bg-red-500 flex items-center justify-center transition-colors"
                  >
                    <X className="w-3 h-3 text-white" />
                  </button>
                </div>
              ) : (
                <div className="relative">
                  <div className="w-[200px] h-[120px] rounded-lg border border-[#1e293b] bg-[#0a0e1a] flex items-center justify-center">
                    {(() => {
                      const FileIcon = getFileIcon(file.type);
                      return <FileIcon className="w-10 h-10 text-slate-600" />;
                    })()}
                  </div>
                  <button
                    onClick={clearFile}
                    className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-red-500/80 hover:bg-red-500 flex items-center justify-center transition-colors"
                  >
                    <X className="w-3 h-3 text-white" />
                  </button>
                </div>
              )}

              <div className="flex-1">
                <p className="text-sm text-slate-300">{file.name}</p>
                <p className="text-xs text-slate-500 mt-1">
                  {file.type} — {(file.size / (1024 * 1024)).toFixed(2)} MB
                </p>
              </div>
            </div>

            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="flex items-center justify-center gap-2 px-6 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <ScanEye className="w-4 h-4" />
              )}
              {loading ? "Analizando..." : "Detectar Deepfake"}
            </button>
          </div>
        )}
      </div>

      {/* Loading */}
      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
            <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 animate-spin" />
            <ScanEye className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <div className="text-center">
            <p className="text-sm text-slate-300">Analizando contenido...</p>
            <p className="text-xs text-slate-500 mt-1">
              Buscando artefactos de manipulación y generación por IA
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
      {result && !loading && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Score + Confidence */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 space-y-5">
            <div className="flex justify-center">
              <RiskGauge score={result.risk_score.total} size={160} />
            </div>

            {confidenceScore !== undefined && (
              <div className="p-3 rounded-lg bg-[#0a0e1a] border border-[#1e293b]">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Percent className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="text-xs text-slate-400">
                      Confianza del análisis
                    </span>
                  </div>
                  <span className="text-sm text-mono font-bold text-cyan-400">
                    {(confidenceScore * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="h-1.5 bg-[#1e293b] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full bg-cyan-400 transition-all duration-1000"
                    style={{ width: `${confidenceScore * 100}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Manipulation Indicators */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-3">
              Indicadores de Manipulación
            </h3>
            {(manipulationIndicators && manipulationIndicators.length > 0
              ? manipulationIndicators
              : result.findings
            ).length === 0 ? (
              <div className="flex items-center gap-2 text-emerald-400 py-4">
                <CheckCircle className="w-5 h-5" />
                <span className="text-sm">
                  No se detectaron manipulaciones
                </span>
              </div>
            ) : (
              <div className="space-y-2 max-h-[300px] overflow-y-auto">
                {(manipulationIndicators && manipulationIndicators.length > 0
                  ? manipulationIndicators
                  : result.findings
                ).map((finding, i) => (
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
          </div>
        </div>
      )}
    </div>
  );
}
