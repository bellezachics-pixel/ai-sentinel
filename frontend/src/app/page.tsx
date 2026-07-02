"use client";

import { useState } from "react";
import AuthGate from "@/components/auth/AuthGate";
import Sidebar, { type ViewType } from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import Dashboard from "@/components/dashboard/Dashboard";
import UniversalScan from "@/components/analysis/UniversalScan";
import InternetAnalyzer from "@/components/analysis/InternetAnalyzer";
import EmailAnalyzer from "@/components/analysis/EmailAnalyzer";
import PhoneSecurity from "@/components/analysis/PhoneSecurity";
import MessageAnalyzer from "@/components/analysis/MessageAnalyzer";
import IdentityCheck from "@/components/analysis/IdentityCheck";
import FileAnalyzer from "@/components/analysis/FileAnalyzer";
import IADetector from "@/components/analysis/IADetector";
import InfoVerifier from "@/components/analysis/InfoVerifier";
import QRScanner from "@/components/analysis/QRScanner";
import NetworkMonitor from "@/components/analysis/NetworkMonitor";
import SentinelChat from "@/components/analysis/SentinelChat";
import PremiumFeatures from "@/components/analysis/PremiumFeatures";

const VIEW_TITLES: Record<ViewType, string> = {
  dashboard: "Panel de Control",
  "universal-scan": "Analizar Cualquier Cosa",
  internet: "Seguridad en Internet",
  correos: "Analizador de Correos",
  telefono: "Seguridad del Telefono",
  mensajes: "Analizador de Mensajes",
  identidad: "Identidad Digital",
  archivos: "Analizador de Archivos",
  "ia-detector": "Detector de IA",
  informacion: "Verificador de Informacion",
  "qr-scanner": "Escaner de Codigos QR",
  red: "Monitor de Red",
  "sentinel-ia": "Sentinel IA",
  premium: "Funciones Premium",
};

export default function Home() {
  const [activeView, setActiveView] = useState<ViewType>("dashboard");

  const renderContent = () => {
    switch (activeView) {
      case "dashboard":
        return <Dashboard />;
      case "universal-scan":
        return <UniversalScan />;
      case "internet":
        return <InternetAnalyzer />;
      case "correos":
        return <EmailAnalyzer />;
      case "telefono":
        return <PhoneSecurity />;
      case "mensajes":
        return <MessageAnalyzer />;
      case "identidad":
        return <IdentityCheck />;
      case "archivos":
        return <FileAnalyzer />;
      case "ia-detector":
        return <IADetector />;
      case "informacion":
        return <InfoVerifier />;
      case "qr-scanner":
        return <QRScanner />;
      case "red":
        return <NetworkMonitor />;
      case "sentinel-ia":
        return <SentinelChat />;
      case "premium":
        return <PremiumFeatures />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <AuthGate>
      {({ user, onLogout }) => (
        <div className="flex h-screen overflow-hidden bg-[#0a0e1a]">
          <Sidebar activeView={activeView} onViewChange={setActiveView} />
          <div className="flex flex-col flex-1 min-w-0">
            <Header
              title={VIEW_TITLES[activeView]}
              username={user.username}
              onLogout={onLogout}
            />
            <main className="flex-1 overflow-y-auto p-6">{renderContent()}</main>
          </div>
        </div>
      )}
    </AuthGate>
  );
}
