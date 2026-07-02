"use client";

import { useState, useRef, useCallback } from "react";
import Image from "next/image";
import {
  QrCode,
  Upload,
  Image as ImageIcon,
  Loader2,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  X,
} from "lucide-react";
import { api } from "@/lib/api";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskColor, getRiskBg } from "@/lib/utils";
import RiskGauge from "@/components/dashboard/RiskGauge";

export default function QRScanner() {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback((f: File) => {
    setFile(f);
    setResult(null);
    setError(null);
    const reader = new FileReader();
    reader.onload = (e) => setPreview(e.target?.result as string);
    reader.readAsDataURL(f);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const f = e.dataTransfer.files[0];
      if (f && f.type.startsWith("image/")) {
        handleFile(f);
      }
    },
    [handleFile]
  );

  const handleAnalyze = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.analyzeQR(file);
      setResult(data);
    } catch {
      setError(
        "No se pudo analizar el código QR. Verifica que la API esté activa."
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

  const decodedUrl = result?.metadata?.decoded_url as string | undefined;

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white">Escáner de Códigos QR</h2>
        <p className="text-sm text-slate-500 mt-0.5">
          Analiza códigos QR para detectar URLs maliciosas ocultas
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
              <Upload className="w-7 h-7 text-cyan-400" />
            </div>
            <div className="text-center">
              <p className="text-sm text-slate-300">
                Arrastra una imagen aquí o{" "}
                <span className="text-cyan-400">haz clic para seleccionar</span>
              </p>
              <p className="text-xs text-slate-500 mt-1">
                PNG, JPG, WEBP — Máximo 10MB
              </p>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFile(f);
              }}
              className="hidden"
            />
          </div>
        ) : (
          <div className="space-y-4">
            {/* Preview */}
            <div className="relative inline-block">
              <div className="rounded-lg overflow-hidden border border-[#1e293b] bg-[#0a0e1a]">
                {preview && (
                  <Image
                    src={preview}
                    alt="QR Code preview"
                    width={250}
                    height={250}
                    unoptimized
                    className="max-w-[250px] max-h-[250px] object-contain"
                  />
                )}
              </div>
              <button
                onClick={clearFile}
                className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-red-500/80 hover:bg-red-500 flex items-center justify-center transition-colors"
              >
                <X className="w-3 h-3 text-white" />
              </button>
            </div>

            <div className="flex items-center gap-3">
              <ImageIcon className="w-4 h-4 text-slate-500" />
              <span className="text-xs text-slate-400 text-mono">
                {file.name}
              </span>
              <span className="text-xs text-slate-600">
                ({(file.size / 1024).toFixed(1)} KB)
              </span>
            </div>

            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="flex items-center justify-center gap-2 px-6 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <QrCode className="w-4 h-4" />
              )}
              {loading ? "Analizando..." : "Analizar QR"}
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
            <QrCode className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <p className="text-sm text-slate-300">Decodificando y analizando QR...</p>
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
          {/* Risk + Decoded URL */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 space-y-4">
            <div className="flex justify-center">
              <RiskGauge score={result.risk_score.total} size={150} />
            </div>
            {decodedUrl && (
              <div className="p-3 rounded-lg bg-[#0a0e1a] border border-[#1e293b]">
                <p className="text-xs text-slate-500 mb-1">URL decodificada:</p>
                <div className="flex items-center gap-2">
                  <ExternalLink className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  <span className="text-xs text-mono text-cyan-400 break-all">
                    {decodedUrl}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Findings */}
          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-3">
              Resultados del Análisis
            </h3>
            {result.findings.length === 0 ? (
              <div className="flex items-center gap-2 text-emerald-400 py-4">
                <CheckCircle className="w-5 h-5" />
                <span className="text-sm">QR seguro — sin amenazas detectadas</span>
              </div>
            ) : (
              <div className="space-y-2 max-h-[300px] overflow-y-auto">
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
      )}
    </div>
  );
}
