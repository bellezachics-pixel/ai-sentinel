"use client";

import { useState } from "react";
import { X, User, Lock, Mail, Loader2 } from "lucide-react";
import { api, setToken } from "@/lib/api";
import { cn } from "@/lib/utils";

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export default function AuthModal({ isOpen, onClose, onSuccess }: AuthModalProps) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res =
        mode === "login"
          ? await api.login(username, password)
          : await api.register(username, password, email);
      setToken(res.access_token);
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || "Error de autenticacion");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-md rounded-2xl bg-[#111827] border border-[#1e293b] p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-bold text-white">
            {mode === "login" ? "Iniciar sesion" : "Crear cuenta"}
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label className="text-xs text-slate-400">Usuario</label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                minLength={3}
                className="w-full h-10 pl-10 pr-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 focus:border-cyan-500/50 focus:outline-none"
              />
            </div>
          </div>

          {mode === "register" && (
            <div className="space-y-2">
              <label className="text-xs text-slate-400">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="w-full h-10 pl-10 pr-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 focus:border-cyan-500/50 focus:outline-none"
                />
              </div>
            </div>
          )}

          <div className="space-y-2">
            <label className="text-xs text-slate-400">Contrasena</label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
                className="w-full h-10 pl-10 pr-4 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 focus:border-cyan-500/50 focus:outline-none"
              />
            </div>
          </div>

          {error && (
            <p className="text-xs text-red-400 bg-red-500/10 p-2 rounded-lg">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full h-10 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {loading && <Loader2 className="w-4 h-4 animate-spin" />}
            {mode === "login" ? "Iniciar sesion" : "Registrarse"}
          </button>
        </form>

        <p className="text-xs text-slate-500 mt-4 text-center">
          {mode === "login" ? "No tienes cuenta? " : "Ya tienes cuenta? "}
          <button
            type="button"
            onClick={() => setMode(mode === "login" ? "register" : "login")}
            className="text-cyan-400 hover:underline"
          >
            {mode === "login" ? "Registrate" : "Inicia sesion"}
          </button>
        </p>
      </div>
    </div>
  );
}
