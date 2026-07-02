"use client";

import { useState, useEffect } from "react";
import { LogOut, Search, Bell, Wifi, WifiOff, Clock, User } from "lucide-react";
import { cn } from "@/lib/utils";

interface HeaderProps {
  title?: string;
  username?: string;
  onLogout?: () => void;
}

export default function Header({ title, username, onLogout }: HeaderProps) {
  const [time, setTime] = useState("");
  const isSecure = true;
  const [searchQuery, setSearchQuery] = useState("");
  const [notifications] = useState(3);

  useEffect(() => {
    const update = () => {
      setTime(
        new Date().toLocaleTimeString("es-ES", {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        })
      );
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-14 bg-[#0d1117]/80 backdrop-blur-sm border-b border-[#1e293b] flex items-center justify-between px-6 shrink-0">
      {/* Left: Title */}
      <div className="flex items-center gap-4">
        {title && (
          <h2 className="text-base font-semibold text-white">{title}</h2>
        )}
      </div>

      {/* Center: Search */}
      <div className="flex-1 max-w-md mx-8">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar amenazas, análisis..."
            className="w-full h-9 pl-10 pr-4 rounded-lg bg-[#111827] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-colors"
          />
        </div>
      </div>

      {/* Right: Status indicators */}
      <div className="flex items-center gap-5">
        {username && (
          <div className="hidden md:flex items-center gap-2 rounded-lg border border-[#1e293b] bg-[#111827] px-3 py-1.5">
            <User className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-xs text-slate-300">{username}</span>
          </div>
        )}

        {/* Network status */}
        <div className="flex items-center gap-2">
          {isSecure ? (
            <Wifi className="w-4 h-4 text-emerald-400" />
          ) : (
            <WifiOff className="w-4 h-4 text-red-400" />
          )}
          <div className="flex items-center gap-1.5">
            <div className="relative">
              <div
                className={cn(
                  "w-2 h-2 rounded-full",
                  isSecure ? "bg-emerald-400" : "bg-red-400"
                )}
              />
              {isSecure && (
                <div className="absolute inset-0 w-2 h-2 rounded-full bg-emerald-400 animate-ping opacity-75" />
              )}
            </div>
            <span className="text-xs text-slate-400 hidden lg:inline">
              {isSecure ? "Seguro" : "Riesgo"}
            </span>
          </div>
        </div>

        {/* Notifications */}
        <button className="relative p-1.5 rounded-lg hover:bg-white/5 transition-colors">
          <Bell className="w-4 h-4 text-slate-400" />
          {notifications > 0 && (
            <span className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full bg-red-500 text-[10px] font-bold text-white flex items-center justify-center">
              {notifications}
            </span>
          )}
        </button>

        {/* Time */}
        <div className="flex items-center gap-1.5 text-slate-500">
          <Clock className="w-3.5 h-3.5" />
          <span className="text-xs text-mono tabular-nums">{time}</span>
        </div>

        {onLogout && (
          <button
            onClick={onLogout}
            className="p-1.5 rounded-lg hover:bg-white/5 transition-colors"
            title="Cerrar sesion"
          >
            <LogOut className="w-4 h-4 text-slate-400 hover:text-red-400" />
          </button>
        )}
      </div>
    </header>
  );
}
