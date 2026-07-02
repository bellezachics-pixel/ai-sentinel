const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "https://ai-sentinel-31so.onrender.com";

const TOKEN_KEY = "ai_sentinel_access_token";
const REFRESH_TOKEN_KEY = "ai_sentinel_refresh_token";
const LEGACY_TOKEN_KEY = "ai_sentinel_token";

export function getAccessToken() {
  if (typeof window === "undefined") return null;
  return (
    window.localStorage.getItem(TOKEN_KEY) ||
    window.localStorage.getItem(LEGACY_TOKEN_KEY)
  );
}

export function setAuthTokens(accessToken: string, refreshToken?: string) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(TOKEN_KEY, accessToken);
  window.localStorage.setItem(LEGACY_TOKEN_KEY, accessToken);
  if (refreshToken) {
    window.localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  }
}

export function clearAuthTokens() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(REFRESH_TOKEN_KEY);
  window.localStorage.removeItem(LEGACY_TOKEN_KEY);
}

export const getToken = getAccessToken;
export const setToken = (token: string) => setAuthTokens(token);
export const clearToken = clearAuthTokens;

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

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface ChatResponse {
  reply: string;
  provider: string;
  model?: string | null;
  configured: boolean;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserProfile {
  id: string;
  username: string;
  email: string;
  is_admin: boolean;
  created_at: string;
}

async function apiFetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const token = getAccessToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...((options?.headers as Record<string, string> | undefined) || {}),
  };

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    throw new Error(`API Error: ${res.status} ${res.statusText}`);
  }

  return res.json();
}

async function apiFormData(endpoint: string, formData: FormData) {
  const token = getAccessToken();
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    body: formData,
  });

  if (!res.ok) {
    throw new Error(`API Error: ${res.status} ${res.statusText}`);
  }

  return res.json() as Promise<AnalysisResult>;
}

type LoginInput = { username: string; password: string } | string;
type RegisterInput =
  | { username: string; email: string; password: string }
  | string;

export const api = {
  login: (credentialsOrUsername: LoginInput, password?: string) => {
    const credentials =
      typeof credentialsOrUsername === "string"
        ? { username: credentialsOrUsername, password: password || "" }
        : credentialsOrUsername;

    return apiFetch<TokenResponse>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    });
  },

  register: (
    dataOrUsername: RegisterInput,
    password?: string,
    email?: string
  ) => {
    const data =
      typeof dataOrUsername === "string"
        ? { username: dataOrUsername, password: password || "", email: email || "" }
        : dataOrUsername;

    return apiFetch<TokenResponse>("/api/v1/auth/register", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getMe: () => apiFetch<UserProfile>("/api/v1/auth/me"),

  me: () =>
    apiFetch<{ username: string; email: string; is_admin: boolean }>(
      "/api/v1/auth/me"
    ),

  logout: () =>
    apiFetch<{ detail: string }>("/api/v1/auth/logout", {
      method: "POST",
    }),

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

  analyzeMessage: (data: { platform: string; body: string }) =>
    apiFetch<AnalysisResult>("/api/v1/analyze/message", {
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

  analyzeFile: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return apiFormData("/api/v1/analyze/file", formData);
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

  chat: (message: string, history: ChatMessage[] = []) =>
    apiFetch<ChatResponse>("/api/v1/chat", {
      method: "POST",
      body: JSON.stringify({ message, history }),
    }),

  healthCheck: () => apiFetch<{ status: string }>("/api/v1/health"),
};
