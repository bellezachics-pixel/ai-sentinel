"use client";

import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

interface RiskGaugeProps {
  score: number;
  size?: number;
}

function getRiskLevel(score: number): {
  label: string;
  color: string;
  strokeColor: string;
} {
  if (score <= 25)
    return {
      label: "Bajo",
      color: "text-emerald-400",
      strokeColor: "#34d399",
    };
  if (score <= 50)
    return { label: "Medio", color: "text-amber-400", strokeColor: "#fbbf24" };
  if (score <= 75)
    return { label: "Alto", color: "text-orange-500", strokeColor: "#f97316" };
  return { label: "Crítico", color: "text-red-500", strokeColor: "#ef4444" };
}

export default function RiskGauge({ score, size = 180 }: RiskGaugeProps) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const risk = getRiskLevel(score);

  const strokeWidth = 10;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (animatedScore / 100) * circumference;
  const dashOffset = circumference - progress;

  useEffect(() => {
    const duration = 1200;
    const steps = 60;
    const increment = score / steps;
    let current = 0;
    const timer = setInterval(() => {
      current += increment;
      if (current >= score) {
        setAnimatedScore(score);
        clearInterval(timer);
      } else {
        setAnimatedScore(Math.floor(current));
      }
    }, duration / steps);
    return () => clearInterval(timer);
  }, [score]);

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          className="transform -rotate-90"
        >
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="#1e293b"
            strokeWidth={strokeWidth}
          />
          {/* Progress circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={risk.strokeColor}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            className="transition-all duration-300"
            style={{
              filter: `drop-shadow(0 0 6px ${risk.strokeColor}40)`,
            }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className={cn(
              "text-3xl font-bold text-mono",
              risk.color
            )}
          >
            {animatedScore}
          </span>
          <span className="text-xs text-slate-500 uppercase tracking-wider">
            Riesgo
          </span>
        </div>
      </div>
      <div className="text-center">
        <span
          className={cn(
            "text-sm font-semibold px-3 py-1 rounded-full",
            score <= 25
              ? "bg-emerald-500/10 text-emerald-400"
              : score <= 50
              ? "bg-amber-500/10 text-amber-400"
              : score <= 75
              ? "bg-orange-500/10 text-orange-500"
              : "bg-red-500/10 text-red-500"
          )}
        >
          Nivel: {risk.label}
        </span>
      </div>
    </div>
  );
}
