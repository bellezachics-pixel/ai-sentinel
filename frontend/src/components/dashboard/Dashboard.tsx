"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { DashboardStats, IntegrationsStatus as IntegrationsStatusType } from "@/lib/api";
import StatsCards from "./StatsCards";
import RiskGauge from "./RiskGauge";
import ThreatDistribution from "./ThreatDistribution";
import RecentAnalyses from "./RecentAnalyses";
import NetworkStatus from "./NetworkStatus";
import IntegrationsStatus from "./IntegrationsStatus";
import { RefreshCw } from "lucide-react";

const MOCK_STATS: DashboardStats = {
  total_scans: 1247,
  threats_detected: 23,
  active_monitors: 5,
  risk_distribution: { low: 892, medium: 278, high: 54, critical: 23 },
  recent_analyses: [
    {
      id: "1",
      analysis_type: "url",
      target: "https://suspicious-login.example.com/verify",
      timestamp: new Date(Date.now() - 300000).toISOString(),
      risk_score: {
        total: 78,
        url_score: 85,
        content_score: 70,
        header_score: 60,
        network_score: 75,
        level: "high",
        breakdown: {},
      },
      findings: [],
      threat_intel: [],
      recommendations: [],
      metadata: {},
    },
    {
      id: "2",
      analysis_type: "email",
      target: "support@bank-secure.com",
      timestamp: new Date(Date.now() - 900000).toISOString(),
      risk_score: {
        total: 92,
        url_score: 0,
        content_score: 95,
        header_score: 88,
        network_score: 0,
        level: "critical",
        breakdown: {},
      },
      findings: [],
      threat_intel: [],
      recommendations: [],
      metadata: {},
    },
    {
      id: "3",
      analysis_type: "network",
      target: "192.168.1.1",
      timestamp: new Date(Date.now() - 1800000).toISOString(),
      risk_score: {
        total: 15,
        url_score: 0,
        content_score: 0,
        header_score: 0,
        network_score: 15,
        level: "low",
        breakdown: {},
      },
      findings: [],
      threat_intel: [],
      recommendations: [],
      metadata: {},
    },
    {
      id: "4",
      analysis_type: "qr",
      target: "qr_code_image.png",
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      risk_score: {
        total: 45,
        url_score: 50,
        content_score: 40,
        header_score: 0,
        network_score: 0,
        level: "medium",
        breakdown: {},
      },
      findings: [],
      threat_intel: [],
      recommendations: [],
      metadata: {},
    },
    {
      id: "5",
      analysis_type: "media",
      target: "video_conference_clip.mp4",
      timestamp: new Date(Date.now() - 7200000).toISOString(),
      risk_score: {
        total: 62,
        url_score: 0,
        content_score: 62,
        header_score: 0,
        network_score: 0,
        level: "high",
        breakdown: {},
      },
      findings: [],
      threat_intel: [],
      recommendations: [],
      metadata: {},
    },
  ],
  network_status: {
    is_secure: true,
    risk_indicators: [],
  },
};

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>(MOCK_STATS);
  const [integrations, setIntegrations] =
    useState<IntegrationsStatusType | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = async () => {
    setLoading(true);
    try {
      const [data, integrationData] = await Promise.all([
        api.getDashboardStats(),
        api.getIntegrationsStatus(),
      ]);
      setStats(data);
      setIntegrations(integrationData);
    } catch {
      // Use mock data silently when API is unavailable
      setStats(MOCK_STATS);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let isMounted = true;

    Promise.all([api.getDashboardStats(), api.getIntegrationsStatus()])
      .then(([data, integrationData]) => {
        if (isMounted) {
          setStats(data);
          setIntegrations(integrationData);
        }
      })
      .catch(() => {
        if (isMounted) {
          setStats(MOCK_STATS);
        }
      })
      .finally(() => {
        if (isMounted) {
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const overallRisk =
    stats.risk_distribution.critical > 0
      ? Math.min(
          100,
          50 +
            stats.risk_distribution.critical * 2 +
            stats.risk_distribution.high
        )
      : stats.risk_distribution.high > 0
      ? Math.min(75, 30 + stats.risk_distribution.high)
      : stats.risk_distribution.medium > 0
      ? Math.min(50, 10 + Math.floor(stats.risk_distribution.medium / 10))
      : 8;

  return (
    <div className="space-y-6 animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">
            Panel de Control
          </h2>
          <p className="text-sm text-slate-500 mt-0.5">
            Resumen de seguridad en tiempo real
          </p>
        </div>
        <button
          onClick={fetchStats}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#111827] border border-[#1e293b] text-sm text-slate-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors disabled:opacity-50"
        >
          <RefreshCw
            className={`w-4 h-4 ${loading ? "animate-spin" : ""}`}
          />
          Actualizar
        </button>
      </div>

      {/* Stats Cards */}
      <StatsCards
        totalScans={stats.total_scans}
        threatsDetected={stats.threats_detected}
        activeMonitors={stats.active_monitors}
        networkSecure={stats.network_status.is_secure}
      />

      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
        <IntegrationsStatus integrations={integrations} loading={loading} />
      </div>

      {/* Middle Row: Risk Gauge + Threat Distribution + Network Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Risk Gauge */}
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5 flex items-center justify-center">
          <RiskGauge score={overallRisk} />
        </div>

        {/* Threat Distribution */}
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
          <ThreatDistribution distribution={stats.risk_distribution} />
        </div>

        {/* Network Status */}
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
          <NetworkStatus
            isSecure={stats.network_status.is_secure}
            riskIndicators={stats.network_status.risk_indicators}
          />
        </div>
      </div>

      {/* Recent Analyses */}
      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
        <h3 className="text-sm font-semibold text-slate-300 mb-4">
          Análisis Recientes
        </h3>
        <RecentAnalyses analyses={stats.recent_analyses} />
      </div>
    </div>
  );
}
