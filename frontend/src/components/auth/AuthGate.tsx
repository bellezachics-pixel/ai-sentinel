"use client";

import { useEffect, useState } from "react";
import {
  ArrowRight,
  Bot,
  FileSearch,
  Globe,
  Lock,
  Loader2,
  LogIn,
  Mail,
  MessageSquare,
  Shield,
  UserPlus,
} from "lucide-react";
import {
  api,
  clearAuthTokens,
  getAccessToken,
  setAuthTokens,
  type UserProfile,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import InstallPrompt from "@/components/pwa/InstallPrompt";

interface AuthGateProps {
  children: (session: {
    user: UserProfile;
    onLogout: () => void;
  }) => React.ReactNode;
}

export default function AuthGate({ children }: AuthGateProps) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [showAuth, setShowAuth] = useState(false);
  const [user, setUser] = useState<UserProfile | null>(null);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(() => Boolean(getAccessToken()));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const hashAccessToken = hashParams.get("access_token");
    const hashRefreshToken = hashParams.get("refresh_token");
    const hashError = hashParams.get("auth_error");

    if (hashAccessToken) {
      setAuthTokens(hashAccessToken, hashRefreshToken || undefined);
      window.history.replaceState(null, "", window.location.pathname);
    } else if (hashError) {
      window.history.replaceState(null, "", window.location.pathname);
      queueMicrotask(() => {
        setError(
          hashError === "google_not_configured"
            ? "Google login todavia no esta configurado."
            : "No se pudo completar el acceso con Google."
        );
      });
    }

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

  const handleGoogleLogin = () => {
    setError(null);
    window.location.href = api.getGoogleLoginUrl();
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

  if (!showAuth) {
    return (
      <div className="min-h-screen bg-[#0a0e1a] text-slate-200">
        <header className="mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10">
              <Shield className="h-5 w-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">AI Sentinel</p>
              <p className="text-[11px] text-cyan-400/70">Ciberseguridad con IA</p>
            </div>
          </div>
          <button
            onClick={() => setShowAuth(true)}
            className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-[#1e293b] bg-[#111827] px-4 text-sm text-slate-200 transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
          >
            Entrar
            <ArrowRight className="h-4 w-4" />
          </button>
        </header>

        <main className="mx-auto grid min-h-[calc(100vh-84px)] max-w-6xl grid-cols-1 gap-8 px-6 pb-8 lg:grid-cols-[1.05fr_0.95fr] lg:items-center">
          <section className="py-6">
            <div className="mb-5 inline-flex items-center gap-2 rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-3 py-2 text-xs font-medium text-cyan-300">
              <Bot className="h-4 w-4" />
              Analisis inteligente para clientes y negocios
            </div>
            <h1 className="max-w-3xl text-4xl font-bold leading-tight text-white md:text-6xl">
              Centinela digital para detectar riesgos antes de hacer clic.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-400">
              Revisa URLs, mensajes, archivos, identidad digital y senales de fraude desde un panel instalable como app. Ideal para demos, clientes y reportes rapidos.
            </p>

            <div className="mt-7 flex flex-col gap-3 sm:flex-row">
              <button
                onClick={handleGoogleLogin}
                className="inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-white px-5 text-sm font-semibold text-slate-950 transition-colors hover:bg-slate-100"
              >
                <Mail className="h-4 w-4 text-red-500" />
                Continuar con Google
              </button>
              <button
                onClick={() => setShowAuth(true)}
                className="inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-cyan-600 px-5 text-sm font-semibold text-white transition-colors hover:bg-cyan-500"
              >
                Crear cuenta
                <ArrowRight className="h-4 w-4" />
              </button>
              <InstallPrompt />
            </div>

            {error && (
              <p className="mt-4 rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-xs text-red-400">
                {error}
              </p>
            )}

            <div className="mt-8 grid grid-cols-1 gap-3 sm:grid-cols-3">
              {[
                { label: "URLs y phishing", icon: Globe },
                { label: "Mensajes sospechosos", icon: MessageSquare },
                { label: "Archivos y hashes", icon: FileSearch },
              ].map((item) => (
                <div
                  key={item.label}
                  className="rounded-lg border border-[#1e293b] bg-[#111827] p-4"
                >
                  <item.icon className="mb-3 h-5 w-5 text-cyan-400" />
                  <p className="text-sm font-medium text-slate-200">{item.label}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-xl border border-[#1e293b] bg-[#0d1117] p-5">
            <div className="mb-4 flex items-center justify-between">
              <p className="text-sm font-semibold text-slate-200">Panel de riesgo</p>
              <span className="rounded-md bg-emerald-500/10 px-2 py-1 text-[11px] font-medium text-emerald-400">
                PWA lista
              </span>
            </div>
            <div className="space-y-3">
              {[
                ["URL sospechosa", "Alto", "78"],
                ["Mensaje de WhatsApp", "Medio", "46"],
                ["Archivo PDF", "Bajo", "18"],
                ["Login con Google", "Activo", "OK"],
              ].map(([name, level, score]) => (
                <div
                  key={name}
                  className="grid grid-cols-[1fr_auto_auto] items-center gap-3 rounded-lg border border-[#1e293b] bg-[#0a0e1a] p-3"
                >
                  <span className="text-sm text-slate-300">{name}</span>
                  <span className="text-xs text-slate-500">{level}</span>
                  <span className="text-sm font-semibold text-cyan-300">{score}</span>
                </div>
              ))}
            </div>
            <div className="mt-5 rounded-lg border border-cyan-500/20 bg-cyan-500/10 p-4">
              <p className="text-sm font-medium text-cyan-300">Reporte listo para cliente</p>
              <p className="mt-1 text-xs leading-5 text-slate-400">
                Resume hallazgos, riesgo y recomendaciones en lenguaje claro para tomar accion rapido.
              </p>
            </div>
          </section>
        </main>

        <footer className="mx-auto flex max-w-6xl flex-col gap-3 border-t border-[#1e293b] px-6 py-5 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <span>AI Sentinel ayuda a evaluar riesgos, no reemplaza asesoria profesional.</span>
          <div className="flex gap-4">
            <a className="hover:text-cyan-300" href="/privacy">Privacidad</a>
            <a className="hover:text-cyan-300" href="/terms">Terminos</a>
            <a className="hover:text-cyan-300" href="/responsible-use">Uso responsable</a>
          </div>
        </footer>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0e1a] text-slate-200 flex items-center justify-center p-6">
      <div className="w-full max-w-md rounded-xl border border-[#1e293b] bg-[#0d1117] p-6">
        <button
          onClick={() => setShowAuth(false)}
          className="mb-5 text-xs text-slate-500 transition-colors hover:text-cyan-300"
        >
          Volver
        </button>
        <div className="flex items-center gap-3 mb-6">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10">
            <Shield className="h-6 w-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">AI-Sentinel</h1>
            <p className="text-xs text-slate-500">Acceso seguro al panel</p>
          </div>
        </div>

        <button
          onClick={handleGoogleLogin}
          className="mb-4 flex h-11 w-full items-center justify-center gap-2 rounded-lg border border-[#1e293b] bg-white text-sm font-medium text-slate-900 transition-colors hover:bg-slate-100"
        >
          <Mail className="h-4 w-4 text-red-500" />
          Continuar con Google
        </button>

        <div className="mb-4 flex items-center gap-3">
          <div className="h-px flex-1 bg-[#1e293b]" />
          <span className="text-[11px] uppercase text-slate-600">
            o usa contrasena
          </span>
          <div className="h-px flex-1 bg-[#1e293b]" />
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
