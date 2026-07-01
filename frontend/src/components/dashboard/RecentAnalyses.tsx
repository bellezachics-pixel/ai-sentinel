"use client";

import {
  Link2,
  Mail,
  QrCode,
  Network,
  ScanEye,
  Search,
  Clock,
  ShieldAlert,
} from "lucide-react";
import { cn, getRiskColor, getRiskBg, formatDate } from "@/lib/utils";
import type { AnalysisResult } from "@/lib/api";

interface RecentAnalysesProps {
  analyses: AnalysisResult[];
}

const TYPE_ICONS: Record<string, React.ElementType> = {
  url: Link2,
  email: Mail,
  qr: QrCode,
  network: Network,
  media: ScanEye,
  threat_intel: Search,
};

const TYPE_LABELS: Record<string, string> = {
  url: "URL",
  email: "Email",
  qr: "QR",
  network: "Red",
  media: "Media",
  threat_intel: "Intel",
};

const LEVEL_LABELS: Record<string, string> = {
  low: "Bajo",
  medium: "Medio",
  high: "Alto",
  critical: "Crítico",
};

export default function RecentAnalyses({ analyses }: RecentAnalysesProps) {
  if (!analyses || analyses.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-slate-500">
        <ShieldAlert className="w-10 h-10 mb-3 text-slate-600" />
        <p className="text-sm">No hay análisis recientes</p>
        <p className="text-xs text-slate-600 mt-1">
          Realiza un escaneo para ver resultados aquí
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#1e293b]">
            <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase tracking-wider font-medium">
              Tipo
            </th>
            <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase tracking-wider font-medium">
              Objetivo
            </th>
            <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase tracking-wider font-medium">
              Riesgo
            </th>
            <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase tracking-wider font-medium">
              Nivel
            </th>
            <th className="text-left py-3 px-3 text-xs text-slate-500 uppercase tracking-wider font-medium">
              Fecha
            </th>
          </tr>
        </thead>
        <tbody>
          {analyses.slice(0, 10).map((analysis, idx) => {
            const Icon =
              TYPE_ICONS[analysis.analysis_type] || ShieldAlert;
            const level = analysis.risk_score?.level || "low";
            return (
              <tr
                key={analysis.id || idx}
                className="border-b border-[#1e293b]/50 hover:bg-white/[0.02] transition-colors"
              >
                <td className="py-3 px-3">
                  <div className="flex items-center gap-2">
                    <Icon className="w-4 h-4 text-slate-400" />
                    <span className="text-xs text-slate-400">
                      {TYPE_LABELS[analysis.analysis_type] ||
                        analysis.analysis_type}
                    </span>
                  </div>
                </td>
                <td className="py-3 px-3">
                  <span
                    className="text-slate-300 text-mono text-xs truncate block max-w-[200px]"
                    title={analysis.target}
                  >
                    {analysis.target}
                  </span>
                </td>
                <td className="py-3 px-3">
                  <span
                    className={cn(
                      "inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold text-mono border",
                      getRiskBg(level),
                      getRiskColor(level)
                    )}
                  >
                    {analysis.risk_score?.total ?? 0}
                  </span>
                </td>
                <td className="py-3 px-3">
                  <span className={cn("text-xs font-medium", getRiskColor(level))}>
                    {LEVEL_LABELS[level] || level}
                  </span>
                </td>
                <td className="py-3 px-3">
                  <div className="flex items-center gap-1.5 text-slate-500">
                    <Clock className="w-3 h-3" />
                    <span className="text-xs text-mono">
                      {analysis.timestamp
                        ? formatDate(analysis.timestamp)
                        : "—"}
                    </span>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
