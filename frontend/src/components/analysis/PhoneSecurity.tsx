"use client";

import { useState } from "react";
import {
  Smartphone, Shield, Eye, AppWindow, Lock, Globe,
  AlertTriangle, CheckCircle, Loader2, RefreshCw,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface SecurityCheck {
  id: string;
  label: string;
  icon: React.ElementType;
  description: string;
  status: "safe" | "warning" | "danger" | "pending" | "checking";
  detail?: string;
}

export default function PhoneSecurity() {
  const [checks, setChecks] = useState<SecurityCheck[]>([
    { id: "device", label: "Estado del dispositivo", icon: Smartphone, description: "Verifica integridad del sistema", status: "pending" },
    { id: "spyware", label: "Deteccion de spyware", icon: Eye, description: "Busca senales de software espia", status: "pending" },
    { id: "apps", label: "Apps peligrosas", icon: AppWindow, description: "Revisa apps con permisos excesivos", status: "pending" },
    { id: "permissions", label: "Permisos excesivos", icon: Lock, description: "Detecta permisos innecesarios", status: "pending" },
    { id: "dns", label: "Configuracion DNS", icon: Globe, description: "Verifica DNS seguro", status: "pending" },
    { id: "vpn", label: "VPN activa", icon: Shield, description: "Verifica conexion VPN", status: "pending" },
    { id: "config", label: "Config. inseguras", icon: AlertTriangle, description: "Detecta configuraciones riesgosas", status: "pending" },
  ]);
  const [scanning, setScanning] = useState(false);
  const [completed, setCompleted] = useState(false);

  const runScan = async () => {
    setScanning(true);
    setCompleted(false);
    const details = [
      "Sistema operativo actualizado, sin jailbreak detectado",
      "No se detectaron procesos sospechosos ni software espia",
      "3 apps con acceso a ubicacion en segundo plano",
      "2 apps con permisos de camara y microfono innecesarios",
      "DNS configurado correctamente (HTTPS/TLS)",
      "No se detecto VPN activa - se recomienda usar una",
      "Bluetooth activo y visible - se recomienda desactivar cuando no se use",
    ];
    const statuses: Array<"safe" | "warning" | "danger"> = [
      "safe", "safe", "warning", "warning", "safe", "warning", "warning"
    ];

    for (let i = 0; i < checks.length; i++) {
      setChecks((prev) =>
        prev.map((c, idx) => (idx === i ? { ...c, status: "checking" } : c))
      );
      await new Promise((r) => setTimeout(r, 800 + Math.random() * 600));
      setChecks((prev) =>
        prev.map((c, idx) =>
          idx === i ? { ...c, status: statuses[i], detail: details[i] } : c
        )
      );
    }
    setScanning(false);
    setCompleted(true);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "safe": return "text-emerald-400";
      case "warning": return "text-amber-400";
      case "danger": return "text-red-400";
      case "checking": return "text-cyan-400";
      default: return "text-slate-500";
    }
  };

  const getStatusBg = (status: string) => {
    switch (status) {
      case "safe": return "bg-emerald-500/10 border-emerald-500/20";
      case "warning": return "bg-amber-500/10 border-amber-500/20";
      case "danger": return "bg-red-500/10 border-red-500/20";
      case "checking": return "bg-cyan-500/10 border-cyan-500/20";
      default: return "bg-[#111827] border-[#1e293b]";
    }
  };

  const safeCount = checks.filter((c) => c.status === "safe").length;
  const warnCount = checks.filter((c) => c.status === "warning").length;
  const dangerCount = checks.filter((c) => c.status === "danger").length;

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Smartphone className="w-6 h-6 text-cyan-400" /> Seguridad del Telefono
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">Revisa la seguridad de tu dispositivo movil</p>
      </div>

      {/* Scan button */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-6 text-center">
        <button
          onClick={runScan}
          disabled={scanning}
          className="inline-flex items-center justify-center gap-2 px-8 h-12 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-base font-semibold transition-all disabled:opacity-50 shadow-lg shadow-cyan-500/20"
        >
          {scanning ? <Loader2 className="w-5 h-5 animate-spin" /> : <RefreshCw className="w-5 h-5" />}
          {scanning ? "Escaneando..." : "Iniciar Escaneo"}
        </button>
        {completed && (
          <div className="flex items-center justify-center gap-4 mt-4">
            <span className="text-sm text-emerald-400">{safeCount} seguros</span>
            <span className="text-sm text-amber-400">{warnCount} alertas</span>
            <span className="text-sm text-red-400">{dangerCount} peligros</span>
          </div>
        )}
      </div>

      {/* Check items */}
      <div className="space-y-2">
        {checks.map((check) => (
          <div
            key={check.id}
            className={cn("rounded-lg border p-4 transition-all duration-300", getStatusBg(check.status))}
          >
            <div className="flex items-center gap-3">
              <check.icon className={cn("w-5 h-5 shrink-0", getStatusColor(check.status))} />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-slate-200">{check.label}</p>
                <p className="text-xs text-slate-500">{check.description}</p>
              </div>
              <div className="shrink-0">
                {check.status === "checking" && <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />}
                {check.status === "safe" && <CheckCircle className="w-4 h-4 text-emerald-400" />}
                {check.status === "warning" && <AlertTriangle className="w-4 h-4 text-amber-400" />}
                {check.status === "danger" && <AlertTriangle className="w-4 h-4 text-red-400" />}
                {check.status === "pending" && <div className="w-4 h-4 rounded-full border border-slate-600" />}
              </div>
            </div>
            {check.detail && (
              <p className={cn("text-xs mt-2 pl-8", getStatusColor(check.status))}>{check.detail}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
