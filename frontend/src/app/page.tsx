"use client";

import { useState } from "react";
import Sidebar, { type ViewType } from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import Dashboard from "@/components/dashboard/Dashboard";
import URLScanner from "@/components/analysis/URLScanner";
import EmailAnalyzer from "@/components/analysis/EmailAnalyzer";
import QRScanner from "@/components/analysis/QRScanner";
import NetworkMonitor from "@/components/analysis/NetworkMonitor";
import DeepfakeDetector from "@/components/analysis/DeepfakeDetector";
import ThreatIntel from "@/components/analysis/ThreatIntel";

const VIEW_TITLES: Record<ViewType, string> = {
  dashboard: "Panel de Control",
  "url-scanner": "Escáner de URLs",
  "email-analyzer": "Analizador de Email",
  "qr-scanner": "Escáner de Códigos QR",
  "network-monitor": "Monitor de Red",
  "deepfake-detector": "Detector de Deepfakes",
  "threat-intel": "Inteligencia de Amenazas",
};

export default function Home() {
  const [activeView, setActiveView] = useState<ViewType>("dashboard");

  const renderContent = () => {
    switch (activeView) {
      case "dashboard":
        return <Dashboard />;
      case "url-scanner":
        return <URLScanner />;
      case "email-analyzer":
        return <EmailAnalyzer />;
      case "qr-scanner":
        return <QRScanner />;
      case "network-monitor":
        return <NetworkMonitor />;
      case "deepfake-detector":
        return <DeepfakeDetector />;
      case "threat-intel":
        return <ThreatIntel />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[#0a0e1a]">
      <Sidebar activeView={activeView} onViewChange={setActiveView} />
      <div className="flex flex-col flex-1 min-w-0">
        <Header title={VIEW_TITLES[activeView]} />
        <main className="flex-1 overflow-y-auto p-6">{renderContent()}</main>
      </div>
    </div>
  );
}
