"use client";

import { useEffect, useMemo, useState } from "react";
import { Download, Smartphone } from "lucide-react";

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed"; platform: string }>;
}

export default function InstallPrompt() {
  const [installEvent, setInstallEvent] =
    useState<BeforeInstallPromptEvent | null>(null);
  const [isIos, setIsIos] = useState(false);
  const [isStandalone, setIsStandalone] = useState(false);

  useEffect(() => {
    const nav = window.navigator;
    const standalone =
      window.matchMedia("(display-mode: standalone)").matches ||
      ("standalone" in nav && Boolean(nav.standalone));
    const ios = /iphone|ipad|ipod/i.test(nav.userAgent);

    queueMicrotask(() => {
      setIsStandalone(standalone);
      setIsIos(ios);
    });

    const handleBeforeInstallPrompt = (event: Event) => {
      event.preventDefault();
      setInstallEvent(event as BeforeInstallPromptEvent);
    };

    window.addEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
    return () => {
      window.removeEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
    };
  }, []);

  const installLabel = useMemo(() => {
    if (isIos) return "Agregar en iPhone";
    return "Instalar app";
  }, [isIos]);

  const handleInstall = async () => {
    if (!installEvent) return;
    await installEvent.prompt();
    await installEvent.userChoice;
    setInstallEvent(null);
  };

  if (isStandalone) return null;

  if (installEvent) {
    return (
      <button
        onClick={handleInstall}
        className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 text-sm font-medium text-cyan-300 transition-colors hover:bg-cyan-500/15"
      >
        <Download className="h-4 w-4" />
        {installLabel}
      </button>
    );
  }

  if (isIos) {
    return (
      <div className="rounded-lg border border-[#1e293b] bg-[#0d1117] p-3 text-xs text-slate-400">
        <div className="mb-1 flex items-center gap-2 text-slate-200">
          <Smartphone className="h-4 w-4 text-cyan-400" />
          Instalable en iPhone
        </div>
        Safari: Compartir y luego Agregar a pantalla de inicio.
      </div>
    );
  }

  return null;
}
