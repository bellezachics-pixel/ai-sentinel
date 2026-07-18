# AI Sentinel - Launch Checklist

## Hecho

- Frontend desplegado en Vercel.
- Backend desplegado en Render.
- Login con Google funcionando.
- PWA instalable con manifest, iconos y service worker.
- Paginas legales basicas: privacidad, terminos y uso responsable.
- Deploy hook de Render conectado a GitHub Actions.
- Endpoints de analisis, chat y dashboard protegidos con login.
- Reporte descargable/copiar por analisis en URL, mensajes y archivos.
- OpenAI, VirusTotal y Google Fact Check configurados en Render.
- Telefono real preparado para Numverify o Twilio Lookup.

## Antes de vender a clientes

- Borrar la API key temporal de Render usada para configuracion.
- Regenerar el Google OAuth Client Secret y actualizarlo en Render.
- Probar flujo completo de cliente:
  - Entrar con Google.
  - Analizar URL.
  - Analizar mensaje.
  - Subir archivo.
  - Copiar o descargar reporte.
  - Revisar dashboard.
- Revisar la app instalada como PWA en iPhone y Android.
- Elegir dominio propio y conectarlo a Vercel.
- Actualizar Google OAuth con el dominio propio cuando exista.
- Opcional: agregar `NUMVERIFY_API_KEY` o Twilio para activar verificacion real de telefonos.
- Opcional: agregar `URLSCAN_API_KEY` y `ABUSEIPDB_API_KEY` para ampliar Threat Intelligence.

## Siguiente fase

- Base de datos real para usuarios y reportes.
- Planes Gratis/Pro conectados al sistema de ventas.
- Branding final: nombre, logo, capturas y textos comerciales.
