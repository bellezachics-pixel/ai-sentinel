import type { Metadata } from "next";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BrainCircuit,
  CheckCircle2,
  CreditCard,
  Eye,
  FileSearch,
  Fingerprint,
  Globe,
  Link2,
  Lock,
  MailWarning,
  MessageSquareWarning,
  QrCode,
  ScanSearch,
  Server,
  Shield,
  ShieldCheck,
  ShieldQuestion,
  Smartphone,
  Sparkles,
  UserX,
  Wifi,
} from "lucide-react";
import LandingHeader from "@/components/landing/LandingHeader";
import FaqAccordion from "@/components/landing/FaqAccordion";

export const metadata: Metadata = {
  title: "CENTINELA — Tu guardián digital | Protección para personas, sin tecnicismos",
  description:
    "CENTINELA analiza enlaces, correos, mensajes, QR, archivos e imágenes para detectar phishing, estafas y señales de manipulación con IA. Prueba 3 días gratis, luego US$16/mes. Cancela cuando quieras.",
  openGraph: {
    title: "CENTINELA — Tu guardián digital",
    description:
      "Protección digital para personas sin conocimientos técnicos: analiza enlaces, correos, mensajes, QR y archivos sospechosos en segundos. 3 días gratis.",
    type: "website",
    locale: "es_419",
    siteName: "CENTINELA",
  },
};

const THREATS = [
  {
    icon: Link2,
    title: "Enlaces de phishing",
    text: "Detecta señales de páginas falsas que imitan bancos, tiendas y servicios para robar tus datos.",
  },
  {
    icon: Globe,
    title: "Suplantación de marcas",
    text: "Identifica dominios imitadores, homoglifos y páginas que se hacen pasar por marcas conocidas.",
  },
  {
    icon: QrCode,
    title: "Códigos QR maliciosos",
    text: "Revisa a dónde apunta realmente ese QR antes de que te redirija a un sitio peligroso.",
  },
  {
    icon: UserX,
    title: "Suplantación de identidad",
    text: "Reconoce patrones de cuentas y mensajes que fingen ser personas de tu confianza.",
  },
  {
    icon: MessageSquareWarning,
    title: "Mensajes de estafa",
    text: "Analiza urgencia artificial, premios falsos, ‘familiares en apuros’ y otras técnicas de engaño.",
  },
  {
    icon: Fingerprint,
    title: "Filtración de tus datos",
    text: "Comprueba si tu correo o contraseña aparecen en filtraciones conocidas de datos.",
  },
];

const TOOLS = [
  {
    icon: Link2,
    title: "Análisis de enlaces y URLs",
    text: "Señales de phishing, homoglifos, impersonación de marcas y reputación del dominio.",
  },
  {
    icon: MailWarning,
    title: "Análisis de correos y mensajes",
    text: "Patrones de ingeniería social: urgencia, premios, solicitudes de credenciales y remitentes falsos.",
  },
  {
    icon: QrCode,
    title: "Seguridad de códigos QR",
    text: "Escanea el destino real de un QR y evalúa si el sitio es seguro antes de abrirlo.",
  },
  {
    icon: FileSearch,
    title: "Análisis de archivos",
    text: "Evalúa archivos sospechosos antes de abrirlos, con señales de riesgo claras.",
  },
  {
    icon: Eye,
    title: "Señales de manipulación con IA",
    text: "Revisa los metadatos de imágenes y audio en busca de indicios de edición o generación artificial.",
  },
  {
    icon: Fingerprint,
    title: "Verificación de identidad",
    text: "Consulta filtraciones de datos con el método k-anonimato: tu contraseña nunca sale de tu dispositivo.",
  },
  {
    icon: Server,
    title: "Chequeo de servidores y redes",
    text: "Verifica certificados TLS, HTTPS y puertos de un objetivo desde los servidores de CENTINELA.",
  },
  {
    icon: BrainCircuit,
    title: "Inteligencia de amenazas",
    text: "Cruza indicadores con VirusTotal, urlscan y AbuseIPDB cuando están configurados.",
  },
  {
    icon: Sparkles,
    title: "Asistente de seguridad con IA",
    text: "Pregunta en lenguaje simple qué hacer ante cualquier situación sospechosa.",
  },
];

const LIMITS = [
  {
    icon: ShieldQuestion,
    title: "Ningún producto detecta el 100% de las amenazas",
    text: "CENTINELA es una capa más de protección, no un escudo absoluto. Combinarlo con buenos hábitos digitales siempre es la mejor estrategia.",
  },
  {
    icon: Eye,
    title: "El análisis de deepfakes se basa en metadatos",
    text: "Revisamos los metadatos de imágenes y audio en busca de señales de manipulación. No es una prueba forense definitiva de autenticidad.",
  },
  {
    icon: Wifi,
    title: "La detección en tu red local requiere el agente opcional",
    text: "El monitoreo de ARP/DNS dentro de tu propia red (Wi-Fi de casa u oficina) necesita nuestro agente local opcional. La versión web analiza objetivos desde los servidores de CENTINELA.",
  },
  {
    icon: Lock,
    title: "Nunca pedimos contraseñas de otros servicios",
    text: "CENTINELA jamás te pedirá la contraseña de tu banco, correo o redes sociales para ‘protegerte’. Si alguien lo hace, es una estafa.",
  },
];

const FAQ_ITEMS = [
  {
    question: "¿Qué pasa cuando terminan mis 3 días gratis?",
    answer:
      "Si no cancelas, se realiza el primer cobro de US$16 y tu suscripción mensual queda activa. Antes de que termine la prueba te mostramos en tu panel la fecha exacta del primer cobro, para que decidas con calma.",
  },
  {
    question: "¿Cómo cancelo mi suscripción?",
    answer:
      "Puedes cancelar en cualquier momento desde tu panel, en la sección de suscripción, o escribiéndonos a hola@centinela.app. La cancelación tiene efecto al final del período en curso: si cancelas durante la prueba, no se realiza ningún cargo.",
  },
  {
    question: "¿Qué datos guardan sobre mí?",
    answer:
      "Guardamos tu correo de cuenta, tu contraseña cifrada y un historial de los análisis que realizas. El contenido que analizas se procesa para darte el resultado y no se conserva después del análisis, salvo que tú mismo guardes un informe. Nunca almacenamos las contraseñas de otros servicios. Puedes pedir la eliminación de tus datos escribiendo a hola@centinela.app.",
  },
  {
    question: "¿Necesito instalar algo en mi computadora o celular?",
    answer:
      "No. CENTINELA funciona completamente desde el navegador, tanto en computadora como en celular, y puedes instalarlo como app (PWA) para acceder más rápido. Solo si quieres monitorear tu red local (Wi-Fi) necesitas nuestro agente opcional.",
  },
  {
    question: "¿Sirve para alguien que no sabe de tecnología?",
    answer:
      "Sí, es exactamente para eso. No necesitas saber qué es un dominio ni un certificado: pegas el enlace, correo o archivo sospechoso y recibes un informe claro con un nivel de riesgo y recomendaciones en lenguaje simple.",
  },
  {
    question: "¿Los pagos son seguros?",
    answer:
      "Los pagos se procesan a través de Stripe, una de las plataformas de pago más usadas del mundo. CENTINELA no almacena los datos de tu tarjeta; la suscripción se gestiona desde el portal seguro de Stripe.",
  },
];

export default function Home() {
  return (
    <div className="min-h-screen bg-[#0a0e1a] text-slate-200">
      <LandingHeader />

      {/* ---------- HERO ---------- */}
      <section className="relative overflow-hidden">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse 60% 45% at 50% 0%, rgba(6,182,212,0.14), transparent 70%)",
          }}
        />
        <div className="relative mx-auto max-w-6xl px-4 pb-20 pt-16 sm:px-6 sm:pt-24">
          <div className="animate-fade-in-up mx-auto max-w-3xl text-center">
            <span className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-4 py-1.5 text-xs font-medium text-cyan-300">
              <ShieldCheck className="h-3.5 w-3.5" />
              Tu guardián digital
            </span>
            <h1 className="mt-6 text-4xl font-bold leading-tight text-white sm:text-5xl">
              Protección digital para personas{" "}
              <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                sin conocimientos técnicos
              </span>
            </h1>
            <p className="mx-auto mt-5 max-w-2xl text-base leading-7 text-slate-400 sm:text-lg">
              ¿Recibiste un enlace raro, un correo que pide tus datos o un
              código QR que no te convence? Pégalo en CENTINELA y en segundos
              sabrás si es una amenaza y qué hacer al respecto. Sin tecnicismos,
              sin alarmismo.
            </p>
            <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <Link
                href="/app"
                className="flex h-12 w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-7 text-sm font-semibold text-white transition-colors hover:bg-cyan-500 sm:w-auto"
              >
                Probar 3 días gratis
                <ArrowRight className="h-4 w-4" />
              </Link>
              <a
                href="#como-funciona"
                className="flex h-12 w-full items-center justify-center rounded-lg border border-[#1e293b] px-7 text-sm font-medium text-slate-300 transition-colors hover:border-cyan-500/30 hover:text-cyan-300 sm:w-auto"
              >
                Ver cómo funciona
              </a>
            </div>
            <p className="mt-4 text-xs text-slate-500">
              3 días gratis · Luego US$16/mes · Cancela cuando quieras · Pagos
              procesados por Stripe
            </p>
          </div>
        </div>
      </section>

      {/* ---------- AMENAZAS ---------- */}
      <section id="amenazas" className="scroll-mt-24 border-t border-[#1e293b]/60">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-2xl font-bold text-white sm:text-3xl">
              Amenazas que te ayuda a identificar
            </h2>
            <p className="mt-3 text-sm leading-6 text-slate-400 sm:text-base">
              Las estafas digitales están diseñadas para apurarte y
              confundirte. CENTINELA las examina con calma, por ti.
            </p>
          </div>
          <div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {THREATS.map((item) => (
              <div
                key={item.title}
                className="gradient-border rounded-xl p-5 transition-colors"
              >
                <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-red-500/20 bg-red-500/10">
                  <item.icon className="h-5 w-5 text-red-400" />
                </span>
                <h3 className="mt-4 text-sm font-semibold text-slate-100">
                  {item.title}
                </h3>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  {item.text}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---------- CÓMO FUNCIONA ---------- */}
      <section
        id="como-funciona"
        className="scroll-mt-24 border-t border-[#1e293b]/60"
      >
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-2xl font-bold text-white sm:text-3xl">
              Cómo funciona
            </h2>
            <p className="mt-3 text-sm leading-6 text-slate-400 sm:text-base">
              Tres pasos, cero tecnicismos.
            </p>
          </div>
          <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-3">
            {[
              {
                step: "1",
                icon: ScanSearch,
                title: "Pega o sube lo sospechoso",
                text: "Un enlace, un correo, un mensaje de WhatsApp, un código QR, un archivo o una imagen. Lo que te llegue, lo analizas.",
              },
              {
                step: "2",
                icon: BrainCircuit,
                title: "CENTINELA lo analiza",
                text: "Nuestros motores revisan señales de phishing, ingeniería social, metadatos, filtraciones de datos e inteligencia de amenazas.",
              },
              {
                step: "3",
                icon: BadgeCheck,
                title: "Recibes un informe claro",
                text: "Un nivel de riesgo fácil de entender, con explicaciones en lenguaje simple y recomendaciones concretas de qué hacer.",
              },
            ].map((step) => (
              <div
                key={step.step}
                className="relative rounded-xl border border-[#1e293b] bg-[#111827] p-6"
              >
                <span className="absolute right-5 top-5 text-mono text-4xl font-bold text-[#1e293b]">
                  {step.step}
                </span>
                <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10">
                  <step.icon className="h-5 w-5 text-cyan-400" />
                </span>
                <h3 className="mt-4 text-sm font-semibold text-slate-100">
                  {step.title}
                </h3>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  {step.text}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---------- QUÉ INCLUYE ---------- */}
      <section
        id="herramientas"
        className="scroll-mt-24 border-t border-[#1e293b]/60"
      >
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-2xl font-bold text-white sm:text-3xl">
              Qué incluye CENTINELA
            </h2>
            <p className="mt-3 text-sm leading-6 text-slate-400 sm:text-base">
              Todas las herramientas en un solo panel, con historial de tus
              análisis y recomendaciones personalizadas.
            </p>
          </div>
          <div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {TOOLS.map((tool) => (
              <div
                key={tool.title}
                className="rounded-xl border border-[#1e293b] bg-[#111827] p-5 transition-colors hover:border-cyan-500/30"
              >
                <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10">
                  <tool.icon className="h-5 w-5 text-cyan-400" />
                </span>
                <h3 className="mt-4 text-sm font-semibold text-slate-100">
                  {tool.title}
                </h3>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  {tool.text}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---------- LÍMITES HONESTOS ---------- */}
      <section className="border-t border-[#1e293b]/60">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20">
          <div className="mx-auto max-w-2xl text-center">
            <span className="inline-flex items-center gap-2 rounded-full border border-amber-500/30 bg-amber-500/10 px-4 py-1.5 text-xs font-medium text-amber-300">
              <AlertTriangle className="h-3.5 w-3.5" />
              Transparencia primero
            </span>
            <h2 className="mt-5 text-2xl font-bold text-white sm:text-3xl">
              Lo que CENTINELA no puede hacer
            </h2>
            <p className="mt-3 text-sm leading-6 text-slate-400 sm:text-base">
              Nos tomamos en serio tu seguridad, y eso incluye ser honestos
              sobre los límites de cualquier herramienta de este tipo.
            </p>
          </div>
          <div className="mt-10 grid grid-cols-1 gap-4 sm:grid-cols-2">
            {LIMITS.map((limit) => (
              <div
                key={limit.title}
                className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-5"
              >
                <div className="flex items-start gap-4">
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-amber-500/20 bg-amber-500/10">
                    <limit.icon className="h-5 w-5 text-amber-400" />
                  </span>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-100">
                      {limit.title}
                    </h3>
                    <p className="mt-2 text-sm leading-6 text-slate-400">
                      {limit.text}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ---------- PRECIOS ---------- */}
      <section id="precios" className="scroll-mt-24 border-t border-[#1e293b]/60">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-24">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-2xl font-bold text-white sm:text-3xl">
              Un solo plan, precio claro
            </h2>
            <p className="mt-3 text-sm leading-6 text-slate-400 sm:text-base">
              Sin planes confusos ni sorpresas. Todo CENTINELA, un precio.
            </p>
          </div>

          <div className="mx-auto mt-10 max-w-md">
            <div className="gradient-border glow-cyan rounded-2xl p-7">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-bold text-white">
                    CENTINELA Pro
                  </h3>
                  <p className="mt-1 text-xs text-slate-500">
                    Todo incluido, siempre
                  </p>
                </div>
                <span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-[11px] font-medium text-cyan-300">
                  3 días gratis
                </span>
              </div>
              <div className="mt-6 flex items-end gap-1">
                <span className="text-4xl font-bold text-white">US$16</span>
                <span className="pb-1.5 text-sm text-slate-500">/mes</span>
              </div>
              <ul className="mt-6 space-y-3">
                {[
                  "Análisis ilimitado de enlaces, correos y mensajes",
                  "Códigos QR, archivos, imágenes y audio",
                  "Verificación de filtraciones de tus datos",
                  "Chequeo de servidores e inteligencia de amenazas",
                  "Asistente de seguridad con IA",
                  "Panel con historial y recomendaciones",
                ].map((feature) => (
                  <li
                    key={feature}
                    className="flex items-start gap-2.5 text-sm text-slate-300"
                  >
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />
                    {feature}
                  </li>
                ))}
              </ul>
              <Link
                href="/app"
                className="mt-7 flex h-12 w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 text-sm font-semibold text-white transition-colors hover:bg-cyan-500"
              >
                Empezar prueba gratis
                <ArrowRight className="h-4 w-4" />
              </Link>
              <p className="mt-4 text-xs leading-5 text-slate-500">
                Primer cobro: al terminar tus 3 días gratis (la fecha exacta se
                muestra en tu panel). Cancela antes sin ningún cargo. Renovación
                mensual automática; cancela cuando quieras desde tu panel o
                escribiéndonos a hola@centinela.app.
              </p>
              <p className="mt-2 flex items-center gap-1.5 text-xs text-slate-500">
                <CreditCard className="h-3.5 w-3.5" />
                Pagos procesados por Stripe
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ---------- FAQ ---------- */}
      <section id="faq" className="scroll-mt-24 border-t border-[#1e293b]/60">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-2xl font-bold text-white sm:text-3xl">
              Preguntas frecuentes
            </h2>
            <p className="mt-3 text-sm leading-6 text-slate-400 sm:text-base">
              Lo esencial, sin letra chica.
            </p>
          </div>
          <div className="mx-auto mt-10 max-w-2xl">
            <FaqAccordion items={FAQ_ITEMS} />
          </div>
        </div>
      </section>

      {/* ---------- CIERRE ---------- */}
      <section className="border-t border-[#1e293b]/60">
        <div className="mx-auto max-w-6xl px-4 py-16 text-center sm:px-6 sm:py-20">
          <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10">
            <Shield className="h-6 w-6 text-cyan-400" />
          </span>
          <h2 className="mx-auto mt-6 max-w-xl text-2xl font-bold text-white sm:text-3xl">
            La próxima estafa no te va a avisar
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-sm leading-6 text-slate-400 sm:text-base">
            Empieza hoy tu prueba gratuita de 3 días y convierte la duda en
            certeza cada vez que algo te parezca sospechoso.
          </p>
          <Link
            href="/app"
            className="mx-auto mt-8 flex h-12 w-full max-w-xs items-center justify-center gap-2 rounded-lg bg-cyan-600 px-7 text-sm font-semibold text-white transition-colors hover:bg-cyan-500"
          >
            Probar 3 días gratis
            <ArrowRight className="h-4 w-4" />
          </Link>
          <p className="mt-3 flex items-center justify-center gap-1.5 text-xs text-slate-500">
            <Smartphone className="h-3.5 w-3.5" />
            Funciona en computadora y celular, sin instalar nada
          </p>
        </div>
      </section>

      {/* ---------- FOOTER ---------- */}
      <footer className="border-t border-[#1e293b]">
        <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
          <div className="flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-center">
            <div className="flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10">
                <Shield className="h-4 w-4 text-cyan-400" />
              </span>
              <div>
                <p className="text-sm font-bold text-white">CENTINELA</p>
                <p className="text-xs text-slate-500">
                  Tu guardián digital
                </p>
              </div>
            </div>
            <nav className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-slate-500">
              <Link className="transition-colors hover:text-cyan-300" href="/privacy">
                Privacidad
              </Link>
              <Link className="transition-colors hover:text-cyan-300" href="/terms">
                Términos de uso
              </Link>
              <Link
                className="transition-colors hover:text-cyan-300"
                href="/responsible-use"
              >
                Uso responsable
              </Link>
              <a
                className="transition-colors hover:text-cyan-300"
                href="mailto:hola@centinela.app"
              >
                hola@centinela.app
              </a>
            </nav>
          </div>
          <p className="mt-8 text-xs text-slate-600">
            © {new Date().getFullYear()} CENTINELA. Los pagos se procesan a
            través de Stripe. Ningún producto de seguridad detecta el 100% de
            las amenazas: usa CENTINELA como parte de buenos hábitos digitales.
          </p>
        </div>
      </footer>
    </div>
  );
}
