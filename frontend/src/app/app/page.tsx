"use client";

import { useState } from "react";
import { Loader2 } from "lucide-react";
import AuthGate from "@/components/auth/AuthGate";
import Sidebar, { type ViewType } from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import Dashboard from "@/components/dashboard/Dashboard";
import UniversalScan from "@/components/analysis/UniversalScan";
import InternetAnalyzer from "@/components/analysis/InternetAnalyzer";
import EmailAnalyzer from "@/components/analysis/EmailAnalyzer";
import URLScanner from "@/components/analysis/URLScanner";
import MessageAnalyzer from "@/components/analysis/MessageAnalyzer";
import IdentityCheck from "@/components/analysis/IdentityCheck";
import FileAnalyzer from "@/components/analysis/FileAnalyzer";
import IADetector from "@/components/analysis/IADetector";
import QRScanner from "@/components/analysis/QRScanner";
import NetworkMonitor from "@/components/analysis/NetworkMonitor";
import DeepfakeDetector from "@/components/analysis/DeepfakeDetector";
import SentinelChat from "@/components/analysis/SentinelChat";
import ThreatIntel from "@/components/analysis/ThreatIntel";
import PremiumFeatures from "@/components/analysis/PremiumFeatures";
import {
  BillingProvider,
  useBilling,
} from "@/components/billing/BillingContext";
import Paywall from "@/components/billing/Paywall";
import TrialBanner from "@/components/billing/TrialBanner";

const VIEW_TITLES: Record<ViewType, string> = {
  dashboard: "Panel de Control",
  "universal-scan": "Analizar Cualquier Cosa",
  internet: "Seguridad en Internet",
  correos: "Analizador de Correos",
  "url-scanner": "Analizar Enlace",
  mensajes: "Analizador de Mensajes",
  identidad: "Identidad Digital",
  archivos: "Analizador de Archivos",
  "ia-detector": "Detector de IA",
  medios: "Análisis de Medios",
  "qr-scanner": "Escaner de Codigos QR",
  red: "Monitor de Red",
  "sentinel-ia": "Sentinel IA",
  "threat-intel": "Inteligencia de Amenazas",
  premium: "Herramientas Pro",
};

function renderView(activeView: ViewType) {
  switch (activeView) {
    case "dashboard":
      return <Dashboard />;
    case "universal-scan":
      return <UniversalScan />;
    case "internet":
      return <InternetAnalyzer />;
    case "correos":
      return <EmailAnalyzer />;
    case "url-scanner":
      return <URLScanner />;
    case "mensajes":
      return <MessageAnalyzer />;
    case "identidad":
      return <IdentityCheck />;
    case "archivos":
      return <FileAnalyzer />;
    case "ia-detector":
      return <IADetector />;
    case "medios":
      return <DeepfakeDetector />;
    case "qr-scanner":
      return <QRScanner />;
    case "red":
      return <NetworkMonitor />;
    case "sentinel-ia":
      return <SentinelChat />;
    case "threat-intel":
      return <ThreatIntel />;
    case "premium":
      return <PremiumFeatures />;
    default:
      return <Dashboard />;
  }
}

/** Banner de prueba gratuita visible sobre el contenido cuando aplica. */
function BillingBanner() {
  const { state } = useBilling();
  if (state.kind !== "ready") return null;
  if (state.billing.status !== "trialing") return null;
  return <TrialBanner trialEnd={state.billing.trial_end} />;
}

/**
 * Contenido principal con control de acceso por plan:
 * - loading: spinner mientras se verifica el plan (sidebar y header visibles)
 * - error: se muestran las herramientas (fail-open) para no bloquear por
 *   fallas del servicio de facturación
 * - sin acceso y fuera de prueba: Paywall en lugar de las herramientas
 */
function GatedView({ activeView }: { activeView: ViewType }) {
  const { state } = useBilling();

  if (state.kind === "loading") {
    return (
      <div className="flex h-full min-h-[50vh] flex-col items-center justify-center gap-4">
        <Loader2 className="h-8 w-8 animate-spin text-cyan-400" />
        <p className="text-sm text-slate-500">Verificando tu plan...</p>
      </div>
    );
  }

  if (state.kind === "error") {
    return <>{renderView(activeView)}</>;
  }

  const locked = !state.billing.has_access && state.billing.status !== "trialing";
  if (locked) {
    return <Paywall />;
  }

  return <>{renderView(activeView)}</>;
}

export default function AppPage() {
  const [activeView, setActiveView] = useState<ViewType>("dashboard");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <AuthGate>
      {({ user, onLogout }) => (
        <BillingProvider>
          <div className="flex h-screen overflow-hidden bg-[#0a0e1a]">
            <Sidebar
              activeView={activeView}
              onViewChange={setActiveView}
              onLogout={onLogout}
              mobileOpen={mobileMenuOpen}
              onMobileClose={() => setMobileMenuOpen(false)}
            />
            <div className="flex flex-col flex-1 min-w-0">
              <Header
                title={VIEW_TITLES[activeView]}
                username={user.username}
                onLogout={onLogout}
                onMenuClick={() => setMobileMenuOpen(true)}
              />
              <BillingBanner />
              <main className="flex-1 overflow-y-auto p-4 md:p-6">
                <GatedView activeView={activeView} />
              </main>
            </div>
          </div>
        </BillingProvider>
      )}
    </AuthGate>
  );
}
