"use client";

import { useState, useRef, useEffect } from "react";
import { MessageCircle, Send, Bot, User, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

const INITIAL_MSG: Message = {
  id: "0",
  role: "assistant",
  content: "Hola! Soy Sentinel IA, tu asistente de ciberseguridad. Puedo ayudarte con:\n\n- Explicar riesgos de seguridad en lenguaje sencillo\n- Dar recomendaciones paso a paso\n- Responder dudas sobre phishing, malware, privacidad\n- Analizar situaciones sospechosas\n\nCuentame, en que te puedo ayudar?",
  timestamp: new Date(),
};

const QUICK_QUESTIONS = [
  "Que es phishing?",
  "Como crear password segura?",
  "Necesito VPN?",
  "Proteger mi WiFi",
  "Tengo malware?",
];

export default function SentinelChat() {
  const [messages, setMessages] = useState<Message[]>([INITIAL_MSG]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEnd = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || loading) return;
    setError(null);

    const userMsg: Message = {
      id: Date.now().toString(),
      role: "user",
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const history = messages
        .filter((m) => m.id !== "0")
        .concat(userMsg)
        .slice(-10)
        .map((m) => ({ role: m.role, content: m.content }));

      const data = await api.chat(history);

      const aiResponse: Message = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: data.response,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, aiResponse]);
    } catch (err: any) {
      setError(err.message || "Error al consultar a Sentinel IA");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] animate-fade-in-up">
      <div className="mb-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <MessageCircle className="w-6 h-6 text-cyan-400" /> Sentinel IA
        </h2>
        <p className="text-sm text-slate-500 mt-0.5">Chat inteligente para dudas de ciberseguridad</p>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto rounded-xl bg-[#111827] border border-[#1e293b] p-4 space-y-4">
        {messages.map((msg) => (
          <div key={msg.id} className={cn("flex gap-3", msg.role === "user" ? "justify-end" : "")}>
            {msg.role === "assistant" && (
              <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0">
                <Bot className="w-4 h-4 text-cyan-400" />
              </div>
            )}
            <div className={cn(
              "max-w-[80%] rounded-xl px-4 py-3 text-sm whitespace-pre-wrap",
              msg.role === "user"
                ? "bg-cyan-600/20 border border-cyan-500/20 text-slate-200"
                : "bg-[#0a0e1a] border border-[#1e293b] text-slate-300"
            )}>
              {msg.content}
            </div>
            {msg.role === "user" && (
              <div className="w-8 h-8 rounded-lg bg-slate-700 flex items-center justify-center shrink-0">
                <User className="w-4 h-4 text-slate-300" />
              </div>
            )}
          </div>
        ))}
        {loading && (
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0">
              <Bot className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="bg-[#0a0e1a] border border-[#1e293b] rounded-xl px-4 py-3">
              <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
            </div>
          </div>
        )}
        {error && (
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs">
            {error}
          </div>
        )}
        <div ref={messagesEnd} />
      </div>

      {/* Quick suggestions */}
      <div className="flex gap-2 mt-3 overflow-x-auto pb-2">
        {QUICK_QUESTIONS.map((q) => (
          <button
            key={q}
            onClick={() => { setInput(q); }}
            className="shrink-0 px-3 py-1.5 rounded-full bg-[#111827] border border-[#1e293b] text-xs text-slate-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="flex gap-3 mt-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSend()}
          placeholder="Escribe tu pregunta de seguridad..."
          className="flex-1 h-11 px-4 rounded-lg bg-[#111827] border border-[#1e293b] text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20"
        />
        <button
          onClick={handleSend}
          disabled={loading || !input.trim()}
          className="flex items-center justify-center w-11 h-11 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-colors disabled:opacity-50"
        >
          <Send className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
