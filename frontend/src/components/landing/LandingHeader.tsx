"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Menu, Shield, X } from "lucide-react";

const NAV_LINKS = [
  { href: "/#amenazas", label: "Amenazas" },
  { href: "/#como-funciona", label: "Cómo funciona" },
  { href: "/#herramientas", label: "Herramientas" },
  { href: "/#precios", label: "Precios" },
  { href: "/#faq", label: "Preguntas" },
];

export default function LandingHeader() {
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Lock body scroll while the mobile menu is open.
  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [open]);

  return (
    <header
      className={`sticky top-0 z-50 border-b border-[#1e293b]/70 bg-[#0a0e1a]/85 backdrop-blur-md transition-shadow ${
        scrolled ? "shadow-[0_4px_24px_rgba(0,0,0,0.35)]" : ""
      }`}
    >
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
        <Link
          href="/"
          className="flex items-center gap-2.5"
          onClick={() => setOpen(false)}
        >
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10">
            <Shield className="h-5 w-5 text-cyan-400" />
          </span>
          <span className="text-base font-bold tracking-wide text-white">
            CENTINELA
          </span>
        </Link>

        {/* Desktop nav */}
        <nav className="hidden items-center gap-7 md:flex">
          {NAV_LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="text-sm text-slate-400 transition-colors hover:text-cyan-300"
            >
              {link.label}
            </Link>
          ))}
        </nav>

        <div className="hidden items-center gap-3 md:flex">
          <Link
            href="/app"
            className="flex h-10 items-center justify-center rounded-lg border border-[#1e293b] px-4 text-sm font-medium text-slate-300 transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
          >
            Acceder
          </Link>
          <Link
            href="/app"
            className="flex h-10 items-center justify-center rounded-lg bg-cyan-600 px-4 text-sm font-medium text-white transition-colors hover:bg-cyan-500"
          >
            Empezar prueba gratis
          </Link>
        </div>

        {/* Mobile toggle */}
        <button
          onClick={() => setOpen((v) => !v)}
          aria-label={open ? "Cerrar menú" : "Abrir menú"}
          className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#1e293b] text-slate-300 md:hidden"
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {/* Mobile menu */}
      {open && (
        <div className="border-t border-[#1e293b] bg-[#0a0e1a]/95 px-4 pb-6 pt-2 backdrop-blur-md md:hidden">
          <nav className="flex flex-col">
            {NAV_LINKS.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                onClick={() => setOpen(false)}
                className="border-b border-[#1e293b]/60 py-3.5 text-sm text-slate-300 transition-colors hover:text-cyan-300"
              >
                {link.label}
              </Link>
            ))}
          </nav>
          <div className="mt-4 flex flex-col gap-3">
            <Link
              href="/app"
              onClick={() => setOpen(false)}
              className="flex h-11 items-center justify-center rounded-lg border border-[#1e293b] text-sm font-medium text-slate-300 transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
            >
              Acceder
            </Link>
            <Link
              href="/app"
              onClick={() => setOpen(false)}
              className="flex h-11 items-center justify-center rounded-lg bg-cyan-600 text-sm font-medium text-white transition-colors hover:bg-cyan-500"
            >
              Empezar prueba gratis
            </Link>
          </div>
        </div>
      )}
    </header>
  );
}
