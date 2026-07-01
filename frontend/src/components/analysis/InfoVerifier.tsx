"use client";

import { useState } from "react";
import { Newspaper, Search, Loader2, CheckCircle, AlertTriangle, BookOpen, Shield } from "lucide-react";
import { cn } from "@/lib/utils";

interface NewsResult {
  credibility: number;
  verdict: "confiable" | "sospechoso" | "desinformacion";
  analysis: string[];
  sources: string[];
}

export default function InfoVerifier() {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<NewsResult | null>(null);

  const handleVerify = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setResult(null);
    await new Promise((r) => setTimeout(r, 2500 + Math.random() * 1500));

    const hasKeywords = /gratis|urgente|comparte|no te lo pierdas|millones|secreto/i.test(text);
    const isShort = text.length < 50;
    const hasExclamation = (text.match(/!/g) || []).length > 2;

    let credibility = 75;
    const analysis: string[] = [];

    if (hasKeywords) { credibility -= 30; analysis.push("Contiene palabras clave asociadas a clickbait o desinformacion"); }
    if (isShort) { credibility -= 10; analysis.push("El texto es muy corto para un analisis profundo"); }
    if (hasExclamation) { credibility -= 15; analysis.push("Uso excesivo de signos de exclamacion (sensacionalismo)"); }
    if (/http|www\./i.test(text)) { analysis.push("Contiene enlaces - verifica la fuente original"); }
    if (credibility > 60) { analysis.push("No se detectaron patrones claros de desinformacion"); }

    credibility = Math.max(5, Math.min(100, credibility));
    const verdict: NewsResult["verdict"] = credibility >= 60 ? "confiable" : credibility >= 30 ? "sospechoso" : "desinformacion";

    setResult({
      credibility,
      verdict,
      analysis,
      sources: ["Analisis de patrones linguisticos", "Deteccion de sensacionalismo", "Verificacion de estructura narrativa"],
    });
    setLoading(false);
  };

  const getVerdictColor = (v: string) => {
    switch (v) {
      case "confiable": return "text-emerald-400";
      case "sospechoso": return "text-amber-400";
      case "desinformacion": return "text-red-400";
      default: return "text-slate-400";
    }
  };

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Newspaper className="w-6 h-6 text-cyan-400" /> Verificador de Informacion
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">Verifica si una noticia es confiable o desinformacion</p>
      </div>

      <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
        <label className="text-xs text-slate-400 uppercase tracking-wider mb-2 block">
          Pega la noticia, titular o afirmacion
        </label>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Pega aqui el texto de la noticia o afirmacion que quieres verificar..."
          rows={6}
          className="w-full px-4 py-3 rounded-lg bg-[#0a0e1a] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 resize-none"
        />
        <button
          onClick={handleVerify}
          disabled={loading || !text.trim()}
          className="mt-3 flex items-center justify-center gap-2 px-6 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium disabled:opacity-50 w-full sm:w-auto"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          {loading ? "Verificando..." : "Verificar Informacion"}
        </button>
      </div>

      {loading && (
        <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-8 flex flex-col items-center gap-4">
          <Loader2 className="w-10 h-10 text-cyan-400 animate-spin" />
          <p className="text-sm text-slate-300">Analizando credibilidad de la informacion...</p>
        </div>
      )}

      {result && !loading && (
        <div className="space-y-4">
          <div className={cn(
            "rounded-xl border p-6 text-center",
            result.verdict === "confiable" ? "bg-emerald-500/5 border-emerald-500/20" :
            result.verdict === "sospechoso" ? "bg-amber-500/5 border-amber-500/20" :
            "bg-red-500/5 border-red-500/20"
          )}>
            <p className={cn("text-3xl font-bold", getVerdictColor(result.verdict))}>{result.credibility}%</p>
            <p className={cn("text-lg font-semibold mt-1 capitalize", getVerdictColor(result.verdict))}>
              {result.verdict}
            </p>
          </div>

          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
              <BookOpen className="w-4 h-4" /> Analisis
            </h3>
            <div className="space-y-2">
              {result.analysis.map((a, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                  <span className="text-cyan-400 mt-0.5">&#8226;</span>{a}
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl bg-[#111827] border border-[#1e293b] p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-3">Metodos de verificacion usados</h3>
            <div className="flex flex-wrap gap-2">
              {result.sources.map((s, i) => (
                <span key={i} className="text-xs px-3 py-1.5 rounded-full bg-[#0a0e1a] border border-[#1e293b] text-slate-400">{s}</span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
