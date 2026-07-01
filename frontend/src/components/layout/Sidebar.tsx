"use client";

import { useState } from "react";
import {
  Shield,
  LayoutDashboard,
  Globe,
  Mail,
  Smartphone,
  MessageSquare,
  Fingerprint,
  FolderOpen,
  Bot,
  Newspaper,
  QrCode,
  Wifi,
  Search,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Crown,
  MessageCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";

export type ViewType =
  | "dashboard"
  | "universal-scan"
  | "internet"
  | "correos"
  | "telefono"
  | "mensajes"
  | "identidad"
  | "archivos"
  | "ia-detector"
  | "informacion"
  | "qr-scanner"
  | "red"
  | "sentinel-ia"
  | "premium";

interface NavItem {
  id: ViewType;
  label: string;
  icon: React.ElementType;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    title: "Principal",
    items: [
      { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
      { id: "universal-scan", label: "Analizar Todo", icon: Search },
    ],
  },
  {
    title: "Analisis",
    items: [
      { id: "internet", label: "Internet", icon: Globe },
      { id: "correos", label: "Correos", icon: Mail },
      { id: "mensajes", label: "Mensajes", icon: MessageSquare },
      { id: "archivos", label: "Archivos", icon: FolderOpen },
      { id: "qr-scanner", label: "QR", icon: QrCode },
    ],
  },
  {
    title: "Seguridad",
    items: [
      { id: "telefono", label: "Telefono", icon: Smartphone },
      { id: "red", label: "Red", icon: Wifi },
      { id: "identidad", label: "Identidad Digital", icon: Fingerprint },
    ],
  },
  {
    title: "Inteligencia",
    items: [
      { id: "ia-detector", label: "Detector IA", icon: Bot },
      { id: "informacion", label: "Informacion", icon: Newspaper },
      { id: "sentinel-ia", label: "Sentinel IA", icon: MessageCircle },
    ],
  },
  {
    title: "Extra",
    items: [
      { id: "premium", label: "Premium", icon: Crown },
    ],
  },
];

interface SidebarProps {
  activeView: ViewType;
  onViewChange: (view: ViewType) => void;
}

export default function Sidebar({ activeView, onViewChange }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [collapsedGroups, setCollapsedGroups] = useState<Record<string, boolean>>({});

  const toggleGroup = (title: string) => {
    setCollapsedGroups((prev) => ({ ...prev, [title]: !prev[title] }));
  };

  return (
    <aside
      className={cn(
        "flex flex-col h-screen bg-[#0d1117] border-r border-[#1e293b] transition-all duration-300 relative z-20",
        collapsed ? "w-[68px]" : "w-[250px]"
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-[#1e293b] shrink-0">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 shrink-0">
          <Shield className="w-5 h-5 text-cyan-400" />
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <h1 className="text-sm font-bold text-white tracking-wide">AI-SENTINEL</h1>
            <p className="text-[10px] text-cyan-400/70 tracking-widest uppercase">v1.0</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2 px-2 overflow-y-auto">
        {navGroups.map((group) => (
          <div key={group.title} className="mb-1">
            {!collapsed && (
              <button
                onClick={() => toggleGroup(group.title)}
                className="flex items-center justify-between w-full px-3 py-1.5 text-[10px] font-semibold text-slate-500 uppercase tracking-wider hover:text-slate-400 transition-colors"
              >
                <span>{group.title}</span>
                {collapsedGroups[group.title] ? (
                  <ChevronDown className="w-3 h-3" />
                ) : (
                  <ChevronUp className="w-3 h-3" />
                )}
              </button>
            )}
            {(!collapsedGroups[group.title] || collapsed) && (
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const isActive = activeView === item.id;
                  const Icon = item.icon;
                  const isUniversal = item.id === "universal-scan";
                  const isPremium = item.id === "premium";
                  return (
                    <button
                      key={item.id}
                      onClick={() => onViewChange(item.id)}
                      className={cn(
                        "flex items-center gap-2.5 w-full px-3 py-2 rounded-lg text-[13px] transition-all duration-200 group",
                        isActive
                          ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-[0_0_10px_#06b6d415]"
                          : "text-slate-400 hover:text-slate-200 hover:bg-white/5 border border-transparent",
                        isUniversal && !isActive && "bg-cyan-600/10 text-cyan-300 border-cyan-500/20 hover:bg-cyan-600/20",
                        isPremium && !isActive && "text-amber-400/80 hover:text-amber-300"
                      )}
                      title={collapsed ? item.label : undefined}
                    >
                      <Icon
                        className={cn(
                          "w-4 h-4 shrink-0 transition-colors",
                          isActive ? "text-cyan-400" : "text-slate-500 group-hover:text-slate-300",
                          isPremium && !isActive && "text-amber-500/70"
                        )}
                      />
                      {!collapsed && (
                        <>
                          <span className="truncate">{item.label}</span>
                          {isActive && (
                            <div className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse shrink-0" />
                          )}
                        </>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        ))}
      </nav>

      {/* Bottom */}
      <div className="border-t border-[#1e293b] p-2 shrink-0">
        <div className={cn("flex items-center gap-3 px-3 py-2 rounded-lg", collapsed ? "justify-center" : "")}>
          <div className="relative shrink-0">
            <div className="w-2 h-2 rounded-full bg-emerald-400" />
            <div className="absolute inset-0 w-2 h-2 rounded-full animate-ping bg-emerald-400" />
          </div>
          {!collapsed && <span className="text-xs text-slate-500">Sistema operativo</span>}
        </div>
      </div>

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="absolute -right-3 top-20 w-6 h-6 rounded-full bg-[#1e293b] border border-[#334155] flex items-center justify-center text-slate-400 hover:text-white hover:bg-[#334155] transition-colors z-30"
      >
        {collapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronLeft className="w-3 h-3" />}
      </button>
    </aside>
  );
}
