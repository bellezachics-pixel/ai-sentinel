"use client";

import { useState, useRef, useEffect } from "react";
import { MessageCircle, Send, Shield, Bot, User, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

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

const AI_RESPONSES: Record<string, string> = {
  phishing: "El phishing es un ataque donde los ciberdelincuentes se hacen pasar por empresas legitimas para robar tus datos.\n\nRecomendaciones:\n1. Nunca hagas clic en enlaces de correos sospechosos\n2. Verifica la URL del remitente\n3. Los bancos NUNCA piden contrasenas por correo\n4. Usa autenticacion de 2 factores\n5. Reporta correos sospechosos",
  password: "Para crear una contrasena segura:\n\n1. Minimo 12 caracteres\n2. Mezcla mayusculas, minusculas, numeros y simbolos\n3. No uses datos personales (nombre, fecha de nacimiento)\n4. No reutilices contrasenas\n5. Usa un gestor de contrasenas como Bitwarden o 1Password\n6. Activa 2FA en todas tus cuentas importantes",
  vpn: "Una VPN (Red Privada Virtual) encripta tu conexion a internet.\n\nCuando usarla:\n- En redes WiFi publicas (cafeterias, aeropuertos)\n- Para proteger tu privacidad del ISP\n- Para evitar rastreo publicitario\n\nRecomendaciones:\n- Usa VPNs de pago confiables (NordVPN, ExpressVPN, ProtonVPN)\n- Evita VPNs gratuitas (pueden vender tus datos)\n- Verifica que no guarden logs",
  wifi: "Para proteger tu red WiFi:\n\n1. Usa WPA3 o WPA2 (nunca WEP)\n2. Cambia la contrasena por defecto del router\n3. Cambia el nombre de la red (SSID)\n4. Desactiva WPS\n5. Actualiza el firmware del router\n6. Usa una contrasena fuerte para el WiFi\n7. Crea una red de invitados separada\n8. Revisa periodicamente los dispositivos conectados",
  malware: "Senales de que tu dispositivo puede tener malware:\n\n- Se vuelve muy lento sin razon\n- Aparecen pop-ups o anuncios inesperados\n- Apps que no instalaste\n- Bateria se agota rapido\n- Uso excesivo de datos\n\nQue hacer:\n1. Escanea con un antivirus confiable\n2. Desinstala apps sospechosas\n3. Actualiza tu sistema operativo\n4. Cambia tus contrasenas desde otro dispositivo\n5. Considera un reset de fabrica si el problema persiste",
};

function getAIResponse(input: string): string {
  const lower = input.toLowerCase();
  for (const [key, response] of Object.entries(AI_RESPONSES)) {
    if (lower.includes(key)) return response;
  }
  if (lower.includes("hola") || lower.includes("hi")) {
    return "Hola! Estoy aqui para ayudarte con cualquier duda de ciberseguridad. Que necesitas saber?";
  }
  if (lower.includes("gracias")) {
    return "De nada! Recuerda que la seguridad digital es un proceso continuo. Si tienes mas dudas, aqui estoy.";
  }
  return `Entiendo tu preocupacion sobre "${input.slice(0, 50)}..."\n\nAqui van algunas recomendaciones generales:\n\n1. Mantén tus dispositivos y apps actualizados\n2. Usa contrasenas unicas y fuertes\n3. Activa la autenticacion de 2 factores\n4. No compartas informacion sensible en redes publicas\n5. Verifica siempre las fuentes antes de hacer clic\n\nQuieres que profundice en algun tema en especifico?`;
}

export default function SentinelChat() {
  const [messages, setMessages] = useState<Message[]>([INITIAL_MSG]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEnd = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || loading) return;
    const userMsg: Message = {
      id: Date.now().toString(),
      role: "user",
      content: input.trim(),
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    await new Promise((r) => setTimeout(r, 1000 + Math.random() * 1500));

    const aiResponse: Message = {
      id: (Date.now() + 1).toString(),
      role: "assistant",
      content: getAIResponse(userMsg.content),
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, aiResponse]);
    setLoading(false);
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
        <div ref={messagesEnd} />
      </div>

      {/* Quick suggestions */}
      <div className="flex gap-2 mt-3 overflow-x-auto pb-2">
        {["Que es phishing?", "Como crear password segura?", "Necesito VPN?", "Proteger mi WiFi", "Tengo malware?"].map((q) => (
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
