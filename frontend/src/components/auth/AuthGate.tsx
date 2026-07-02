"use client";

import { useEffect, useState } from "react";
import { Lock, Loader2, LogIn, Shield, UserPlus } from "lucide-react";
import {
  api,
  clearAuthTokens,
  getAccessToken,
  setAuthTokens,
  type UserProfile,
} from "@/lib/api";
import { cn } from "@/lib/utils";

interface AuthGateProps {
  children: (session: {
    user: UserProfile;
    onLogout: () => void;
  }) => React.ReactNode;
}

export default function AuthGate({ children }: AuthGateProps) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [user, setUser] = useState<UserProfile | null>(null);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(() => Boolean(getAccessToken()));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = getAccessToken();
    if (!token) {
      return;
    }

    api
      .getMe()
      .then(setUser)
      .catch(() => {
        clearAuthTokens();
      })
      .finally(() => setLoading(false));
  }, []);

  const handleSubmit = async () => {
    if (!username.trim() || !password.trim()) return;
    if (mode === "register" && !email.trim()) return;

    setSubmitting(true);
    setError(null);
    try {
      const tokens =
        mode === "login"
          ? await api.login({ username: username.trim(), password })
          : await api.register({
              username: username.trim(),
              email: email.trim(),
              password,
            });
      setAuthTokens(tokens.access_token, tokens.refresh_token);
      const profile = await api.getMe();
      setUser(profile);
    } catch {
      setError(
        mode === "login"
          ? "No se pudo iniciar sesion. Revisa usuario y contrasena."
          : "No se pudo crear la cuenta. Usa una contrasena fuerte y datos validos."
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleLogout = () => {
    api.logout().catch(() => undefined);
    clearAuthTokens();
    setUser(null);
    setPassword("");
  };

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-[#0a0e1a]">
        <Loader2 className="h-8 w-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  if (user) {
    return <>{children({ user, onLogout: handleLogout })}</>;
  }

  return (
    <div className="min-h-screen bg-[#0a0e1a] text-slate-200 flex items-center justify-center p-6">
      <div className="w-full max-w-md rounded-xl border border-[#1e293b] bg-[#0d1117] p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10">
            <Shield className="h-6 w-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">AI-Sentinel</h1>
            <p className="text-xs text-slate-500">Acceso seguro al panel</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 mb-5">
          {[
            { id: "login", label: "Entrar", icon: LogIn },
            { id: "register", label: "Crear", icon: UserPlus },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setMode(item.id as "login" | "register");
                setError(null);
              }}
              className={cn(
                "h-10 rounded-lg border text-sm flex items-center justify-center gap-2 transition-colors",
                mode === item.id
                  ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-400"
                  : "border-[#1e293b] bg-[#111827] text-slate-400 hover:text-slate-200"
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </button>
          ))}
        </div>

        <div className="space-y-3">
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            placeholder="Usuario"
            className="h-11 w-full rounded-lg border border-[#1e293b] bg-[#0a0e1a] px-4 text-sm text-slate-200 outline-none focus:border-cyan-500/50"
          />
          {mode === "register" && (
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              placeholder="Email"
              type="email"
              className="h-11 w-full rounded-lg border border-[#1e293b] bg-[#0a0e1a] px-4 text-sm text-slate-200 outline-none focus:border-cyan-500/50"
            />
          )}
          <input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            placeholder="Contrasena"
            type="password"
            className="h-11 w-full rounded-lg border border-[#1e293b] bg-[#0a0e1a] px-4 text-sm text-slate-200 outline-none focus:border-cyan-500/50"
          />
        </div>

        {error && (
          <p className="mt-3 rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-xs text-red-400">
            {error}
          </p>
        )}

        <button
          onClick={handleSubmit}
          disabled={submitting || !username.trim() || !password.trim()}
          className="mt-5 flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 text-sm font-medium text-white transition-colors hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Lock className="h-4 w-4" />
          )}
          {mode === "login" ? "Iniciar sesion" : "Crear cuenta"}
        </button>

        {mode === "register" && (
          <p className="mt-3 text-xs text-slate-500">
            La contrasena debe tener mayuscula, numero y caracter especial.
          </p>
        )}
      </div>
    </div>
  );
}
