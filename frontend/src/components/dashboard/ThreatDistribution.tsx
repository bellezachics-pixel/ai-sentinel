"use client";

import dynamic from "next/dynamic";

const LazyPieChart = dynamic(
  () => import("recharts").then((m) => ({ default: m.PieChart })),
  { ssr: false }
);
const LazyPie = dynamic(
  () => import("recharts").then((m) => ({ default: m.Pie })),
  { ssr: false }
);
const LazyCell = dynamic(
  () => import("recharts").then((m) => ({ default: m.Cell })),
  { ssr: false }
);
const LazyTooltip = dynamic(
  () => import("recharts").then((m) => ({ default: m.Tooltip })),
  { ssr: false }
);
const LazyResponsiveContainer = dynamic(
  () => import("recharts").then((m) => ({ default: m.ResponsiveContainer })),
  { ssr: false }
);

interface ThreatDistributionProps {
  distribution: Record<string, number>;
}

const RISK_COLORS: Record<string, string> = {
  low: "#34d399",
  medium: "#fbbf24",
  high: "#f97316",
  critical: "#ef4444",
};

const RISK_LABELS: Record<string, string> = {
  low: "Bajo",
  medium: "Medio",
  high: "Alto",
  critical: "Crítico",
};

export default function ThreatDistribution({
  distribution,
}: ThreatDistributionProps) {
  const data = Object.entries(distribution).map(([key, value]) => ({
    name: RISK_LABELS[key] || key,
    value,
    color: RISK_COLORS[key] || "#64748b",
  }));

  const total = data.reduce((sum, d) => sum + d.value, 0);

  if (total === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500">
        <p className="text-sm">Sin datos de distribución</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <h3 className="text-sm font-semibold text-slate-300 mb-4">
        Distribución de Amenazas
      </h3>
      <div className="flex-1 min-h-[200px]">
        <LazyResponsiveContainer width="100%" height="100%">
          <LazyPieChart>
            <LazyPie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={75}
              paddingAngle={3}
              dataKey="value"
              strokeWidth={0}
            >
              {data.map((entry, index) => (
                <LazyCell key={`cell-${index}`} fill={entry.color} />
              ))}
            </LazyPie>
            <LazyTooltip
              contentStyle={{
                backgroundColor: "#1e293b",
                border: "1px solid #334155",
                borderRadius: "8px",
                color: "#e2e8f0",
                fontSize: "12px",
              }}
            />
          </LazyPieChart>
        </LazyResponsiveContainer>
      </div>
      {/* Legend */}
      <div className="grid grid-cols-2 gap-2 mt-3">
        {data.map((item) => (
          <div key={item.name} className="flex items-center gap-2">
            <div
              className="w-2.5 h-2.5 rounded-full shrink-0"
              style={{ backgroundColor: item.color }}
            />
            <span className="text-xs text-slate-400 truncate">
              {item.name}
            </span>
            <span className="text-xs text-mono text-slate-300 ml-auto">
              {item.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
