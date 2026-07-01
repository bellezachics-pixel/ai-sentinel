const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "https://ai-sentinel-31so.onrender.com";

export interface AnalysisResult {
  id: string;
  analysis_type: string;
  target: string;
  timestamp: string;
  risk_score: RiskScore;
  findings: Finding[];
  threat_intel: ThreatIntelResult[];
  recommendations: string[];
  metadata: Record<string, unknown>;
}

export interface RiskScore {
  total: number;
  url_score: number;
  content_score: number;
  header_score: number;
  network_score: number;
  level: "low" | "medium" | "high" | "critical";
  breakdown: Record<string, unknown>;
}

export interface Finding {
  type: string;
  severity: string;
  description: string;
  source?: string;
  details?: Record<string, unknown>;
}

export interface ThreatIntelResult {
  source: string;
  score: number;
  is_malicious: boolean;
  details: Record<string, unknown>;
}

export interface DashboardStats {
  total_scans: number;
  threats_detected: number;
  active_monitors: number;
  risk_distribution: Record<string, number>;
  recent_analyses: AnalysisResult[];
  network_status: {
    is_secure: boolean;
    risk_indicators: string[];
  };
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("ai_sentinel_token");
}

export function setToken(token: string) {
  if (typeof window !== "undefined") {
    localStorage.setItem("ai_sentinel_token", token);
  }
}

export function clearToken() {
  if (typeof window !== "undefined") {
    localStorage.removeItem("ai_sentinel_token");
  }
}

async function apiFetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...options?.headers,
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    headers,
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API Error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

function apiFormData(endpoint: string, formData: FormData) {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return fetch(`${API_BASE}${endpoint}`, {
    method: "POST",
    headers,
    body: formData,
  }).then((r) => r.json() as Promise<AnalysisResult>);
}

export const api = {
  analyzeUrl: (url: string, deep_scan = false) =>
    apiFetch<AnalysisResult>("/api/v1/analyze/url", {
      method: "POST",
      body: JSON.stringify({ url, deep_scan }),
    }),

  analyzeEmail: (data: { subject: string; sender: string; body: string }) =>
    apiFetch<AnalysisResult>("/api/v1/analyze/email", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  analyzeQR: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return apiFormData("/api/v1/analyze/qr", formData);
  },

  analyzeMedia: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return apiFormData("/api/v1/analyze/media", formData);
  },

  checkNetwork: (target_ip?: string) =>
    apiFetch<AnalysisResult>("/api/v1/analyze/network", {
      method: "POST",
      body: JSON.stringify({ target_ip }),
    }),

  checkIdentity: (value: string, check_type: string) =>
    apiFetch<AnalysisResult>("/api/v1/analyze/identity", {
      method: "POST",
      body: JSON.stringify({ value, check_type }),
    }),

  threatIntelLookup: (indicator: string, indicator_type = "url") =>
    apiFetch<{ indicator: string; results: ThreatIntelResult[] }>(
      "/api/v1/threat-intel/lookup",
      {
        method: "POST",
        body: JSON.stringify({ indicator, indicator_type }),
      }
    ),

  getDashboardStats: () => apiFetch<DashboardStats>("/api/v1/dashboard/stats"),

  healthCheck: () => apiFetch<{ status: string }>("/api/v1/health"),

  login: (username: string, password: string) =>
    apiFetch<AuthResponse>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  register: (username: string, password: string, email: string) =>
    apiFetch<AuthResponse>("/api/v1/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, password, email }),
    }),

  me: () =>
    apiFetch<{ username: string; email: string; is_admin: boolean }>(
      "/api/v1/auth/me"
    ),
};
