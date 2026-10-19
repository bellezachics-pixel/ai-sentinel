const CACHE_NAME = "guardiaflow-pwa-v2-gf1";
const APP_SHELL = ["/", "/manifest.webmanifest", "/icons/icon-192.png", "/icons/icon-512.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))
      )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);

  if (request.method !== "GET" || url.pathname.startsWith("/api/")) {
    return;
  }

  // NUNCA cachear payloads RSC de Next ni datos de rutas: servirian
  // interfaces viejas aunque el cache se haya actualizado.
  if (
    request.headers.has("RSC") ||
    url.searchParams.has("_rsc") ||
    url.pathname.startsWith("/_next/data")
  ) {
    return;
  }

  if (request.mode === "navigate") {
    // Las navegaciones siempre van a red: cachear HTML de pagina sirve
    // versiones desactualizadas del shell.
    event.respondWith(
      fetch(request).catch(() => caches.match("/"))
    );
    return;
  }

  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;

      return fetch(request).then((response) => {
        // Solo cachear assets estaticos versionados por Next (hashes en
        // la ruta): nunca HTML de pagina ni respuestas opacas.
        const isVersionedAsset =
          url.origin === self.location.origin &&
          (url.pathname.startsWith("/_next/static") ||
            url.pathname.startsWith("/icons/"));
        if (response.ok && isVersionedAsset) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        }
        return response;
      });
    })
  );
});
