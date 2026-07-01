import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI-Sentinel | Ciberseguridad Inteligente",
  description:
    "Plataforma de ciberseguridad impulsada por IA para detección de amenazas, análisis de URLs, correos, QR, deepfakes y monitoreo de red.",
  keywords: [
    "ciberseguridad",
    "AI",
    "threat detection",
    "phishing",
    "deepfake",
    "network security",
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" className="h-full antialiased">
      <body className="min-h-full bg-[#0a0e1a] text-slate-200">{children}</body>
    </html>
  );
}
