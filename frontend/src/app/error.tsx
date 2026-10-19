"use client";

export default function GlobalError({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center px-6 text-center">
      <h2 className="text-xl font-bold text-white mb-2">
        Algo salió mal 😔
      </h2>
      <p className="text-sm text-slate-400 mb-6 max-w-md">
        Ocurrió un error inesperado. Tus datos están a salvo; intenta recargar.
      </p>
      <button
        onClick={reset}
        className="px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 font-medium text-sm hover:bg-cyan-400 transition"
      >
        Reintentar
      </button>
    </div>
  );
}
