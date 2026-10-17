// Protección del entorno de pruebas (staging).
// Solo activa HTTP Basic Auth cuando STAGING_PASSWORD está definida y no vacía:
//   STAGING_PASSWORD=tu-clave-segura   -> protege el sitio (usuario: cualquiera, ej. "gabi")
//   STAGING_PASSWORD=                  -> sin protección (comportamiento de producción)
import { NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  const stagingPassword = process.env.STAGING_PASSWORD;
  if (!stagingPassword) {
    return NextResponse.next();
  }

  const authHeader = request.headers.get("authorization");
  if (authHeader?.startsWith("Basic ")) {
    const decoded = atob(authHeader.slice(6));
    const separator = decoded.indexOf(":");
    const password = separator === -1 ? "" : decoded.slice(separator + 1);
    if (password === stagingPassword) {
      return NextResponse.next();
    }
  }

  return new NextResponse("Acceso restringido al área de pruebas.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Área de pruebas", charset="UTF-8"',
    },
  });
}

export const config = {
  matcher: [
    // Aplica a todo excepto assets estáticos que deben cargar sin desafío.
    "/((?!_next/static|_next/image|favicon.ico|manifest.webmanifest|icons/).*)",
  ],
};
