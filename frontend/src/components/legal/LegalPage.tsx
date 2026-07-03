import Link from "next/link";
import { Shield } from "lucide-react";

interface LegalPageProps {
  title: string;
  updated: string;
  sections: Array<{
    heading: string;
    body: string;
  }>;
}

export default function LegalPage({ title, updated, sections }: LegalPageProps) {
  return (
    <main className="min-h-screen bg-[#0a0e1a] px-6 py-8 text-slate-200">
      <div className="mx-auto max-w-3xl">
        <Link
          href="/"
          className="mb-8 inline-flex items-center gap-3 text-sm text-slate-400 transition-colors hover:text-cyan-300"
        >
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10">
            <Shield className="h-4 w-4 text-cyan-400" />
          </span>
          Volver a AI Sentinel
        </Link>

        <header className="mb-8">
          <h1 className="text-3xl font-bold text-white">{title}</h1>
          <p className="mt-2 text-sm text-slate-500">Actualizado: {updated}</p>
        </header>

        <div className="space-y-5 rounded-xl border border-[#1e293b] bg-[#0d1117] p-6">
          {sections.map((section) => (
            <section key={section.heading}>
              <h2 className="text-base font-semibold text-slate-100">
                {section.heading}
              </h2>
              <p className="mt-2 text-sm leading-7 text-slate-400">
                {section.body}
              </p>
            </section>
          ))}
        </div>
      </div>
    </main>
  );
}
