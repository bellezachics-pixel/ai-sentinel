"use client";

import {
  AlertTriangle,
  AppWindow,
  CheckCircle,
  Eye,
  Globe,
  Lock,
  Shield,
  Smartphone,
  Wifi,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface GuidanceItem {
  id: string;
  label: string;
  icon: React.ElementType;
  status: "available" | "manual" | "limited";
  detail: string;
  action: string;
}

const guidance: GuidanceItem[] = [
  {
    id: "links",
    label: "Enlaces y mensajes",
    icon: Globe,
    status: "available",
    detail: "Centinela si puede analizar URLs, QR, correos y mensajes sospechosos.",
    action: "Usa URL, Mensajes, Correos o QR para revisar evidencia real.",
  },
  {
    id: "files",
    label: "Archivos recibidos",
    icon: Shield,
    status: "available",
    detail: "Puedes subir PDFs, ZIPs, APKs e imagenes para revisar metadata, hash y reputacion.",
    action: "Sube el archivo en Analizador de Archivos antes de abrirlo.",
  },
  {
    id: "spyware",
    label: "Spyware instalado",
    icon: Eye,
    status: "limited",
    detail: "Una web/PWA no puede leer procesos internos ni apps instaladas del telefono.",
    action: "Revisa consumo de bateria, apps desconocidas y perfiles/VPN instalados desde ajustes del sistema.",
  },
  {
    id: "apps",
    label: "Apps peligrosas",
    icon: AppWindow,
    status: "manual",
    detail: "Centinela no tiene permiso para listar tus apps desde el navegador.",
    action: "Elimina apps que no reconozcas y revisa permisos de ubicacion, camara, microfono y accesibilidad.",
  },
  {
    id: "permissions",
    label: "Permisos excesivos",
    icon: Lock,
    status: "manual",
    detail: "Los permisos del telefono se revisan desde Android/iOS, no desde la web.",
    action: "Deja permisos sensibles en 'Preguntar siempre' o 'Solo mientras se usa la app'.",
  },
  {
    id: "network",
    label: "Red y modem",
    icon: Wifi,
    status: "available",
    detail: "Centinela puede revisar señales de red contra un objetivo, pero no controla el modem.",
    action: "Usa Monitor de Red y cambia la clave del WiFi si sospechas acceso no autorizado.",
  },
];

const statusStyles = {
  available: {
    label: "Disponible",
    icon: CheckCircle,
    className: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400",
  },
  manual: {
    label: "Revision manual",
    icon: AlertTriangle,
    className: "bg-amber-500/10 border-amber-500/20 text-amber-400",
  },
  limited: {
    label: "Limitado en web",
    icon: AlertTriangle,
    className: "bg-slate-500/10 border-slate-500/20 text-slate-400",
  },
};

export default function PhoneSecurity() {
  const availableCount = guidance.filter((item) => item.status === "available").length;
  const manualCount = guidance.filter((item) => item.status === "manual").length;
  const limitedCount = guidance.filter((item) => item.status === "limited").length;

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Smartphone className="w-6 h-6 text-cyan-400" /> Seguridad del Telefono
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">
          Guia honesta para revisar tu telefono desde Centinela web
        </p>
      </div>

      <div className="rounded-xl bg-cyan-500/5 border border-cyan-500/20 p-5">
        <div className="flex items-start gap-3">
          <Shield className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="text-sm font-semibold text-cyan-300">
              Importante
            </h3>
            <p className="text-xs text-slate-400 mt-1 leading-5">
              En navegador o PWA, Centinela no puede leer procesos, spyware,
              apps instaladas ni permisos internos del telefono. Para un
              diagnostico profundo se necesita una app movil nativa o una
              herramienta MDM/antivirus. Aqui te mostramos que se puede revisar
              desde la web y que debes validar manualmente.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg bg-[#111827] border border-emerald-500/20 p-3 text-center">
          <p className="text-lg font-bold text-emerald-400">{availableCount}</p>
          <p className="text-[11px] text-slate-500">Reales desde web</p>
        </div>
        <div className="rounded-lg bg-[#111827] border border-amber-500/20 p-3 text-center">
          <p className="text-lg font-bold text-amber-400">{manualCount}</p>
          <p className="text-[11px] text-slate-500">Manual</p>
        </div>
        <div className="rounded-lg bg-[#111827] border border-slate-500/20 p-3 text-center">
          <p className="text-lg font-bold text-slate-400">{limitedCount}</p>
          <p className="text-[11px] text-slate-500">Limitado</p>
        </div>
      </div>

      <div className="space-y-3">
        {guidance.map((item) => {
          const style = statusStyles[item.status];
          const StatusIcon = style.icon;

          return (
            <div
              key={item.id}
              className="rounded-lg border border-[#1e293b] bg-[#111827] p-4"
            >
              <div className="flex items-start gap-3">
                <item.icon className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                    <p className="text-sm font-medium text-slate-200">
                      {item.label}
                    </p>
                    <span
                      className={cn(
                        "inline-flex w-fit items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium",
                        style.className
                      )}
                    >
                      <StatusIcon className="w-3 h-3" />
                      {style.label}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-2 leading-5">
                    {item.detail}
                  </p>
                  <p className="text-xs text-slate-300 mt-2 leading-5">
                    {item.action}
                  </p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
