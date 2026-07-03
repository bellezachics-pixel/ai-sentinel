"use client";

import { useMemo, useState } from "react";
import { Check, Clipboard, Download, FileText, ShieldCheck } from "lucide-react";
import type { AnalysisResult } from "@/lib/api";
import { cn, getRiskBg, getRiskColor } from "@/lib/utils";

type SecurityReportProps = {
  result: AnalysisResult;
  title?: string;
};

const riskLabels: Record<string, string> = {
  low: "Bajo",
  medium: "Medio",
  high: "Alto",
  critical: "Critico",
};

function formatDate(value?: string) {
  if (!value) return new Date().toLocaleString("es-MX");
  return new Date(value).toLocaleString("es-MX");
}

function buildReport(result: AnalysisResult, title: string) {
  const score = Math.round(result.risk_score.total);
  const riskLevel = riskLabels[result.risk_score.level] || result.risk_score.level;
  const findings =
    result.findings.length > 0
      ? result.findings
          .map(
            (finding, index) =>
              `${index + 1}. [${finding.severity.toUpperCase()}] ${finding.type}: ${finding.description}`
          )
          .join("\n")
      : "No se encontraron amenazas significativas.";
  const recommendations =
    result.recommendations.length > 0
      ? result.recommendations
          .map((recommendation, index) => `${index + 1}. ${recommendation}`)
          .join("\n")
      : "Mantener buenas practicas y evitar compartir informacion sensible.";

  return [
    "AI Sentinel - Reporte de Seguridad",
    title,
    "",
    `Fecha: ${formatDate(result.timestamp)}`,
    `Tipo de analisis: ${result.analysis_type}`,
    `Objetivo: ${result.target}`,
    `Riesgo: ${score}/100 (${riskLevel})`,
    "",
    "Hallazgos:",
    findings,
    "",
    "Recomendaciones:",
    recommendations,
    "",
    "Nota: Este reporte es una evaluacion automatizada y debe revisarse junto con el contexto del caso.",
  ].join("\n");
}

function reportFileName(result: AnalysisResult) {
  const target = result.target
    .replace(/[^a-z0-9]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  const safeTarget = target || "analisis";
  return `ai-sentinel-${safeTarget}-${new Date().toISOString().slice(0, 10)}.txt`;
}

async function copyToClipboard(text: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
}

export default function SecurityReport({
  result,
  title = "Reporte del analisis",
}: SecurityReportProps) {
  const [copied, setCopied] = useState(false);
  const reportText = useMemo(() => buildReport(result, title), [result, title]);
  const score = Math.round(result.risk_score.total);
  const riskLevel = riskLabels[result.risk_score.level] || result.risk_score.level;
  const topFindings = result.findings.slice(0, 3);

  const handleCopy = async () => {
    await copyToClipboard(reportText);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  const handleDownload = () => {
    const blob = new Blob([reportText], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = reportFileName(result);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3 min-w-0">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center shrink-0">
            <FileText className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
            <p className="text-xs text-slate-500 mt-1 break-words">
              Listo para copiar, guardar o enviar al cliente.
            </p>
          </div>
        </div>

        <div className="flex gap-2 shrink-0">
          <button
            onClick={handleCopy}
            className="inline-flex items-center justify-center gap-2 h-9 px-3 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-xs text-slate-300 hover:text-cyan-300 hover:border-cyan-500/30 transition-colors"
          >
            {copied ? <Check className="w-4 h-4" /> : <Clipboard className="w-4 h-4" />}
            {copied ? "Copiado" : "Copiar"}
          </button>
          <button
            onClick={handleDownload}
            className="inline-flex items-center justify-center gap-2 h-9 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-medium text-white transition-colors"
          >
            <Download className="w-4 h-4" />
            Descargar
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
        <div className="rounded-lg bg-[#0a0e1a]/50 border border-[#1e293b] p-3">
          <p className="text-[10px] uppercase text-slate-500 mb-1">Riesgo</p>
          <div className="flex items-center gap-2">
            <ShieldCheck className={cn("w-4 h-4", getRiskColor(result.risk_score.level))} />
            <span
              className={cn(
                "text-xs font-semibold px-2 py-0.5 rounded border",
                getRiskBg(result.risk_score.level),
                getRiskColor(result.risk_score.level)
              )}
            >
              {score}/100 - {riskLevel}
            </span>
          </div>
        </div>
        <div className="rounded-lg bg-[#0a0e1a]/50 border border-[#1e293b] p-3">
          <p className="text-[10px] uppercase text-slate-500 mb-1">Hallazgos</p>
          <p className="text-xs text-slate-300">
            {result.findings.length} alerta{result.findings.length === 1 ? "" : "s"} detectada
            {result.findings.length === 1 ? "" : "s"}
          </p>
        </div>
        <div className="rounded-lg bg-[#0a0e1a]/50 border border-[#1e293b] p-3">
          <p className="text-[10px] uppercase text-slate-500 mb-1">Fecha</p>
          <p className="text-xs text-slate-300">{formatDate(result.timestamp)}</p>
        </div>
      </div>

      {topFindings.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[#1e293b]">
          <p className="text-xs font-semibold text-slate-400 uppercase mb-2">
            Resumen principal
          </p>
          <div className="space-y-2">
            {topFindings.map((finding, index) => (
              <p key={`${finding.type}-${index}`} className="text-xs text-slate-400">
                <span className={cn("font-semibold", getRiskColor(finding.severity))}>
                  {finding.type}:
                </span>{" "}
                {finding.description}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
