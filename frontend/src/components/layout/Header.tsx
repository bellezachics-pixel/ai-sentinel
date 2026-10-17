"use client";

import { useState, useEffect } from "react";
import { LogOut, Clock, User, Menu } from "lucide-react";

interface HeaderProps {
  title?: string;
  username?: string;
  onLogout?: () => void;
  onMenuClick?: () => void;
}

export default function Header({ title, username, onLogout, onMenuClick }: HeaderProps) {
  const [time, setTime] = useState("");

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
    <header className="h-14 bg-[#0d1117]/80 backdrop-blur-sm border-b border-[#1e293b] flex items-center justify-between gap-3 px-4 md:px-6 shrink-0">
      {/* Left: Title */}
      <div className="flex min-w-0 items-center gap-3 md:gap-4">
        <button
          onClick={onMenuClick}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#1e293b] bg-[#111827] text-slate-400 transition-colors hover:text-cyan-400 md:hidden"
          aria-label="Abrir menu"
        >
          <Menu className="h-4 w-4" />
        </button>
        {title && (
          <h2 className="truncate text-sm font-semibold text-white md:text-base">{title}</h2>
        )}
      </div>

      {/* Right: Status indicators */}
      <div className="flex items-center gap-2 md:gap-5">
        {username && (
          <div className="hidden md:flex items-center gap-2 rounded-lg border border-[#1e293b] bg-[#111827] px-3 py-1.5">
            <User className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-xs text-slate-300">{username}</span>
          </div>
        )}

        {/* Time */}
        <div className="hidden items-center gap-1.5 text-slate-500 md:flex">
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
