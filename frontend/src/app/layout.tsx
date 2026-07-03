import type { Metadata, Viewport } from "next";
import ServiceWorkerRegister from "@/components/pwa/ServiceWorkerRegister";
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
  applicationName: "AI Sentinel",
  manifest: "/manifest.webmanifest",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "AI Sentinel",
  },
  icons: {
    icon: [
      { url: "/icons/icon-192.png", sizes: "192x192", type: "image/png" },
      { url: "/icons/icon-512.png", sizes: "512x512", type: "image/png" },
    ],
    apple: [{ url: "/icons/apple-touch-icon.png", sizes: "180x180" }],
  },
};

export const viewport: Viewport = {
  themeColor: "#06b6d4",
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  viewportFit: "cover",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" className="h-full antialiased">
      <body className="min-h-full bg-[#0a0e1a] text-slate-200">
        <ServiceWorkerRegister />
        {children}
      </body>
    </html>
  );
}
