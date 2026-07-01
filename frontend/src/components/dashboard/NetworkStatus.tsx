"use client";

import { Shield, Lock, Globe, Network as NetworkIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface NetworkStatusProps {
  isSecure: boolean;
  riskIndicators: string[];
}

export default function NetworkStatus({
  isSecure,
  riskIndicators,
}: NetworkStatusProps) {
  const statuses = [
    {
      label: "Conexión",
      status: isSecure ? "Segura" : "Comprometida",
      ok: isSecure,
      icon: Shield,
    },
    {
      label: "TLS/SSL",
      status: isSecure ? "Verificado" : "Alerta",
      ok: isSecure,
      icon: Lock,
    },
    {
      label: "DNS",
      status:
        riskIndicators.some((r) => r.toLowerCase().includes("dns"))
          ? "Anomalía"
          : "Normal",
      ok: !riskIndicators.some((r) => r.toLowerCase().includes("dns")),
      icon: Globe,
    },
    {
      label: "ARP",
      status:
        riskIndicators.some((r) => r.toLowerCase().includes("arp"))
          ? "Spoofing"
          : "Normal",
      ok: !riskIndicators.some((r) => r.toLowerCase().includes("arp")),
      icon: NetworkIcon,
    },
  ];

  return (
    <div className="flex flex-col h-full">
      <h3 className="text-sm font-semibold text-slate-300 mb-4">
        Integridad de Red
      </h3>

      {/* Connection diagram */}
      <div className="flex items-center justify-center mb-5">
        <svg width="200" height="60" viewBox="0 0 200 60">
          {/* Device */}
          <rect
            x="5"
            y="18"
            width="30"
            height="24"
            rx="4"
            fill="#1e293b"
            stroke={isSecure ? "#34d399" : "#ef4444"}
            strokeWidth="1.5"
          />
          <rect x="12" y="24" width="16" height="12" rx="2" fill="#0a0e1a" />

          {/* Connection line */}
          <line
            x1="40"
            y1="30"
            x2="85"
            y2="30"
            stroke={isSecure ? "#34d399" : "#ef4444"}
            strokeWidth="1.5"
            strokeDasharray={isSecure ? "none" : "4 2"}
          />

          {/* Shield / Firewall */}
          <g transform="translate(85, 15)">
            <path
              d="M15 0 L30 8 L30 20 Q30 30 15 35 Q0 30 0 20 L0 8 Z"
              fill={isSecure ? "#06b6d420" : "#ef444420"}
              stroke={isSecure ? "#06b6d4" : "#ef4444"}
              strokeWidth="1.5"
            />
            {isSecure ? (
              <path
                d="M10 17 L14 21 L22 13"
                fill="none"
                stroke="#06b6d4"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            ) : (
              <>
                <line
                  x1="10"
                  y1="13"
                  x2="20"
                  y2="23"
                  stroke="#ef4444"
                  strokeWidth="2"
                  strokeLinecap="round"
                />
                <line
                  x1="20"
                  y1="13"
                  x2="10"
                  y2="23"
                  stroke="#ef4444"
                  strokeWidth="2"
                  strokeLinecap="round"
                />
              </>
            )}
          </g>

          {/* Connection line 2 */}
          <line
            x1="120"
            y1="30"
            x2="160"
            y2="30"
            stroke={isSecure ? "#34d399" : "#ef4444"}
            strokeWidth="1.5"
            strokeDasharray={isSecure ? "none" : "4 2"}
          />

          {/* Cloud / Internet */}
          <g transform="translate(160, 15)">
            <ellipse
              cx="18"
              cy="15"
              rx="18"
              ry="12"
              fill="#1e293b"
              stroke={isSecure ? "#34d399" : "#ef4444"}
              strokeWidth="1.5"
            />
            <text
              x="18"
              y="18"
              textAnchor="middle"
              fill="#64748b"
              fontSize="8"
              fontFamily="monospace"
            >
              WAN
            </text>
          </g>
        </svg>
      </div>

      {/* Status items */}
      <div className="space-y-2.5 flex-1">
        {statuses.map((s) => {
          const Icon = s.icon;
          return (
            <div
              key={s.label}
              className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#0a0e1a]/50"
            >
              <div className="flex items-center gap-2.5">
                <Icon
                  className={cn(
                    "w-3.5 h-3.5",
                    s.ok ? "text-emerald-400" : "text-red-400"
                  )}
                />
                <span className="text-xs text-slate-400">{s.label}</span>
              </div>
              <div className="flex items-center gap-2">
                <div
                  className={cn(
                    "w-1.5 h-1.5 rounded-full",
                    s.ok ? "bg-emerald-400" : "bg-red-400"
                  )}
                />
                <span
                  className={cn(
                    "text-xs font-medium",
                    s.ok ? "text-emerald-400" : "text-red-400"
                  )}
                >
                  {s.status}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Risk indicators */}
      {riskIndicators.length > 0 && (
        <div className="mt-3 pt-3 border-t border-[#1e293b]">
          <p className="text-xs text-slate-500 mb-2">Indicadores de riesgo:</p>
          <div className="space-y-1">
            {riskIndicators.map((indicator, i) => (
              <p key={i} className="text-xs text-red-400/80 flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-red-400 shrink-0" />
                {indicator}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
