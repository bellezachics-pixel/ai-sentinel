"use client";

import { useEffect, useState } from "react";
import { Shield, AlertTriangle, Activity, Wifi } from "lucide-react";
import { cn } from "@/lib/utils";

interface StatCard {
  label: string;
  value: number;
  icon: React.ElementType;
  color: string;
  bgColor: string;
  borderColor: string;
  suffix?: string;
}

interface StatsCardsProps {
  totalScans: number;
  threatsDetected: number;
  activeMonitors: number;
  networkSecure: boolean;
}

export default function StatsCards({
  totalScans,
  threatsDetected,
  activeMonitors,
  networkSecure,
}: StatsCardsProps) {
  const cards: StatCard[] = [
    {
      label: "Escaneos Totales",
      value: totalScans,
      icon: Shield,
      color: "text-cyan-400",
      bgColor: "bg-cyan-500/10",
      borderColor: "border-cyan-500/20",
    },
    {
      label: "Amenazas Detectadas",
      value: threatsDetected,
      icon: AlertTriangle,
      color: "text-red-400",
      bgColor: "bg-red-500/10",
      borderColor: "border-red-500/20",
    },
    {
      label: "Monitores Activos",
      value: activeMonitors,
      icon: Activity,
      color: "text-blue-400",
      bgColor: "bg-blue-500/10",
      borderColor: "border-blue-500/20",
    },
    {
      label: "Estado de Red",
      value: networkSecure ? 1 : 0,
      icon: Wifi,
      color: networkSecure ? "text-emerald-400" : "text-red-400",
      bgColor: networkSecure ? "bg-emerald-500/10" : "bg-red-500/10",
      borderColor: networkSecure
        ? "border-emerald-500/20"
        : "border-red-500/20",
      suffix: networkSecure ? "Seguro" : "Riesgo",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card) => (
        <StatCardItem key={card.label} card={card} />
      ))}
    </div>
  );
}

function StatCardItem({ card }: { card: StatCard }) {
  const [displayValue, setDisplayValue] = useState(card.suffix ? card.value : 0);
  const Icon = card.icon;

  useEffect(() => {
    if (card.suffix) {
      return;
    }
    const target = card.value;
    const duration = 1000;
    const steps = 30;
    const increment = target / steps;
    let current = 0;
    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        setDisplayValue(target);
        clearInterval(timer);
      } else {
        setDisplayValue(Math.floor(current));
      }
    }, duration / steps);
    return () => clearInterval(timer);
  }, [card.value, card.suffix]);

  return (
    <div
      className={cn(
        "relative rounded-xl bg-[#111827] border p-4 transition-all duration-300 hover:bg-[#1a2332] group overflow-hidden",
        card.borderColor
      )}
    >
      {/* Subtle gradient overlay */}
      <div className="absolute inset-0 bg-gradient-to-br from-white/[0.02] to-transparent pointer-events-none" />

      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">
            {card.label}
          </p>
          {card.suffix ? (
            <p className={cn("text-xl font-bold text-mono", card.color)}>
              {card.suffix}
            </p>
          ) : (
            <p className={cn("text-2xl font-bold text-mono", card.color)}>
              {displayValue.toLocaleString()}
            </p>
          )}
        </div>
        <div
          className={cn(
            "w-10 h-10 rounded-lg flex items-center justify-center transition-transform group-hover:scale-110",
            card.bgColor
          )}
        >
          <Icon className={cn("w-5 h-5", card.color)} />
        </div>
      </div>
    </div>
  );
}
