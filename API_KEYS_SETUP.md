# AI Sentinel - Guia de API Keys

Esta guia lista las claves que faltan para activar las funciones reales de la app.
No pegues estas claves en chats publicos. Agregalas directo en Render:

`Render Dashboard` -> `ai-sentinel` -> `Environment` -> `Edit` -> `Add Environment Variable` -> `Save`.

## Prioridad 1 - lanzamiento

### OpenAI

Variable:

```env
OPENAI_API_KEY=
```

Activa:

- Sentinel IA chat.
- Analisis inteligente de mensajes.
- Vision para imagenes/detector IA cuando este conectado.

Modelos actuales:

```env
OPENAI_CHAT_MODEL=gpt-4o-mini
OPENAI_VISION_MODEL=gpt-4o-mini
```

### VirusTotal

Variable:

```env
VIRUSTOTAL_API_KEY=
```

Activa:

- Reputacion real de URLs.
- Reputacion real de archivos por hash.
- Mejor evidencia para reportes de seguridad.

Plan gratis: util para pruebas y lanzamiento inicial, con limite bajo de uso.

### Google Fact Check

Variable:

```env
GOOGLE_FACT_CHECK_API_KEY=
```

Activa:

- Verificador de noticias.
- Revision basica de desinformacion con fuentes de fact-checking.

## Prioridad 2 - telefono

Elige una opcion para comenzar.

### Numverify

Variable:

```env
NUMVERIFY_API_KEY=
```

Mas simple para validar numeros y mostrar informacion basica.

### Twilio Lookup

Variables:

```env
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_LOOKUP_FROM_COUNTRY=US
```

Mas profesional para producto final, pero normalmente requiere cuenta con billing.

## Seguridad pendiente

Estas acciones son importantes porque algunas claves se usaron durante configuracion:

- Regenerar `GOOGLE_OAUTH_CLIENT_SECRET` en Google Cloud y actualizarlo en Render.
- Borrar o regenerar la Render API Key temporal.
- Mantener `REQUIRE_AUTH_FOR_ANALYSIS=true` en Render.

## Como verificar

Despues de guardar variables en Render:

1. Espera que Render termine el redeploy.
2. Entra a la app.
3. Abre el dashboard.
4. Revisa la tarjeta `Integraciones`.
5. Las integraciones configuradas deben aparecer como `Activa`.
