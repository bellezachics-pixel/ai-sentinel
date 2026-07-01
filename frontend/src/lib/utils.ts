import { clsx, type ClassValue } from "clsx";

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function getRiskColor(level: string): string {
  switch (level) {
    case "low":
      return "text-emerald-400";
    case "medium":
      return "text-amber-400";
    case "high":
      return "text-orange-500";
    case "critical":
      return "text-red-500";
    default:
      return "text-gray-400";
  }
}

export function getRiskBg(level: string): string {
  switch (level) {
    case "low":
      return "bg-emerald-500/10 border-emerald-500/30";
    case "medium":
      return "bg-amber-500/10 border-amber-500/30";
    case "high":
      return "bg-orange-500/10 border-orange-500/30";
    case "critical":
      return "bg-red-500/10 border-red-500/30";
    default:
      return "bg-gray-500/10 border-gray-500/30";
  }
}

export function getRiskGradient(level: string): string {
  switch (level) {
    case "low":
      return "from-emerald-500 to-emerald-600";
    case "medium":
      return "from-amber-500 to-amber-600";
    case "high":
      return "from-orange-500 to-orange-600";
    case "critical":
      return "from-red-500 to-red-600";
    default:
      return "from-gray-500 to-gray-600";
  }
}

export function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleString("es-ES", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
