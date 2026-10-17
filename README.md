# Guardia Flow - Ciberseguridad Avanzada con IA

**Guardia Flow** (guardiaflow.com) es una aplicacion de ciberseguridad potente con deteccion de phishing, intervencion de datos por IA (AiTM), QRishing, Deepfakes y Threat Intelligence en tiempo real.

## Arquitectura

| Componente | Tecnologia | Funcion |
|---|---|---|
| Frontend | Next.js 16 + React + Tailwind CSS | Dashboard de riesgo, visualizacion de red |
| Backend | FastAPI (Python 3.11+) | Procesamiento asincrono, orquestacion de IA |
| Motor de IA | Scikit-learn + OpenAI API | Clasificacion, deteccion de anomalias, NLP |

## Modulos

- **URL Analyzer** - Analisis heuristico de URLs (phishing, homografos, patrones maliciosos)
- **Content Analyzer** - Deteccion de ingenieria social, formularios de captura de credenciales
- **Header Analyzer** - Verificacion de cabeceras de seguridad, certificados TLS
- **Network Integrity Guard** - Deteccion AiTM, monitoreo ARP/DNS, baseline de comportamiento
- **QRishing Detector** - Escaneo de codigos QR, analisis de URLs embebidas
- **Deepfake Detector** - Analisis de metadatos de imagen/audio/video
- **Threat Intelligence** - Integracion con VirusTotal, Urlscan.io, AbuseIPDB
- **OCR & NLP** - Extraccion de texto de imagenes, deteccion de spear phishing

## Inicio Rapido

### Opcion 1: Script automatico
```bash
./start.sh
```

### Opcion 2: Manual

**Backend:**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### Opcion 3: Docker
```bash
docker compose up --build
```

### Tests
```bash
cd backend
.venv/bin/python -m pytest tests/ -q
```
Los tests usan un directorio de datos temporal; no tocan los JSON reales.

## URLs

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Docs (Swagger):** http://localhost:8000/docs

## PWA instalable

El frontend incluye manifest, iconos y service worker para instalarlo como app desde el navegador.

- En iPhone/iPad: Safari -> Compartir -> Agregar a pantalla de inicio.
- En Android/Chrome: menu del navegador -> Instalar app o Agregar a pantalla principal.

## API Keys (Opcionales)

Crear archivo `.env` en la raiz del backend:

```env
VIRUSTOTAL_API_KEY=tu_api_key
URLSCAN_API_KEY=tu_api_key
ABUSEIPDB_API_KEY=tu_api_key
OPENAI_API_KEY=tu_api_key
OPENAI_CHAT_MODEL=gpt-4o-mini
OPENAI_VISION_MODEL=gpt-4o-mini
GOOGLE_FACT_CHECK_API_KEY=tu_api_key
GOOGLE_OAUTH_CLIENT_ID=tu_google_client_id
GOOGLE_OAUTH_CLIENT_SECRET=tu_google_client_secret
GOOGLE_OAUTH_REDIRECT_URI=http://localhost:8000/api/v1/auth/google/callback
FRONTEND_URL=http://localhost:3000
NUMVERIFY_API_KEY=tu_api_key
TWILIO_ACCOUNT_SID=tu_account_sid
TWILIO_AUTH_TOKEN=tu_auth_token
TWILIO_LOOKUP_FROM_COUNTRY=US
REQUIRE_AUTH_FOR_ANALYSIS=false
```

La app funciona sin API keys con capacidades reducidas (analisis local solamente).

### Login con Google/Gmail

Crear credenciales OAuth 2.0 en Google Cloud y configurar estas variables en Render:

```env
GOOGLE_OAUTH_CLIENT_ID=...
GOOGLE_OAUTH_CLIENT_SECRET=...
GOOGLE_OAUTH_REDIRECT_URI=https://TU-BACKEND-RENDER.onrender.com/api/v1/auth/google/callback
FRONTEND_URL=https://guardiaflow.com
```

En Google Cloud, agregar el mismo valor de `GOOGLE_OAUTH_REDIRECT_URI` en **Authorized redirect URIs**.

## Pasarela de pago (Stripe TEST)

Guardia Flow ofrece **3 dias de trial gratis** y despues una suscripcion de **US$16/mes**.
La pasarela esta implementada **exclusivamente en modo TEST**: jamas uses claves live
de Stripe en este proyecto.

### Configuracion

```bash
cd backend
cp .env.example .env
# Editar .env:
STRIPE_SECRET_KEY=sk_test_...        # clave secreta TEST del dashboard
STRIPE_WEBHOOK_SECRET=whsec_...      # signing secret (ver abajo)
STRIPE_PRICE_ID=price_...            # opcional; ver nota
BILLING_ENFORCE=true                 # exigir trial/suscripcion en analisis
ADMIN_EMAILS=admin@example.com       # opcional; emails con rol de admin (coma)
```

- Si `STRIPE_PRICE_ID` se deja vacio, el backend busca (o crea) el producto
  **"Guardia Flow Pro"** (USD 16/mes recurrente) en la cuenta TEST y registra el
  price ID en los logs para pegarlo en el `.env`.
- Sin `STRIPE_SECRET_KEY`, el backend opera en **modo trial-only**: el checkout
  responde `503 pasarela_no_configurada` y solo el trial de 3 dias otorga acceso.

### Webhook local

Instala el CLI de Stripe (https://docs.stripe.com/stripe-cli) y reenvia los
eventos al backend en desarrollo:

```bash
stripe listen --forward-to localhost:8000/api/v1/billing/webhook
```

El comando imprime un signing secret (`whsec_...`): copialo a
`STRIPE_WEBHOOK_SECRET`. El endpoint verifica la firma `Stripe-Signature` con
el cuerpo crudo del request y esta **exento del rate limiting** (los reintentos
de Stripe no deben bloquearse).

### Endpoints

| Metodo | Ruta | Auth | Descripcion |
|---|---|---|---|
| POST | `/api/v1/billing/checkout` | JWT | URL de Stripe Checkout (409 si ya hay suscripcion activa, 503 si no hay pasarela) |
| POST | `/api/v1/billing/portal` | JWT | URL del portal de facturacion (404 sin customer de Stripe) |
| GET | `/api/v1/billing/status` | JWT | `has_access`, `status`, `trial_end`, `plan_price` ("US$16/mes") |
| POST | `/api/v1/billing/webhook` | firma Stripe | Recibe `checkout.session.completed`, `customer.subscription.*`, `invoice.payment_failed` |
| GET | `/api/v1/billing/payments` | JWT | Historial de cobros del customer (max 20, mas recientes primero; `[]` sin customer, 503 sin pasarela) |
| POST | `/api/v1/billing/admin/refund` | JWT admin | Reembolso administrativo (`payment_id` = `cs_`/`pi_`/`ch_`, `reason` y `amount` opcionales; 403 sin rol admin) |

Eventos procesados: `checkout.session.completed` (vincula customer/suscripcion
al usuario), `customer.subscription.updated` / `.deleted`,
`invoice.payment_failed` (sincronizan estado en `backend/data/billing.json`),
`invoice.payment_succeeded` (guarda `last_payment_*` y renova
`current_period_end`) y `charge.refunded` / `charge.refund.updated` (reembolso
completo -> status `refunded`: sin acceso aunque el trial local siga vivo).

Flujo de reembolsos: el admin crea el refund con
`POST /api/v1/billing/admin/refund` (admite `cs_...`, `pi_...` o `ch_...`,
con `reason` en `duplicate|fraudulent|requested_by_customer` y `amount` en
centavos para reembolso parcial) o directamente en el dashboard de Stripe
TEST; en ambos casos el webhook marca el reembolso en el store local.

### Enforcement

Con `BILLING_ENFORCE=true`, los endpoints de analisis, chat y dashboard exigen
trial vigente o suscripcion activa/trialing; si no, responden
`402 trial_expirado_o_suscripcion_requerida`. Los usuarios **anonimos**
conservan el comportamiento anterior segun `REQUIRE_AUTH_FOR_ANALYSIS`
(sin cambios respecto a versiones previas). Los administradores (`is_admin`)
siempre tienen acceso.

**Activacion en LIVE (fuera de alcance por ahora):** crear producto/precio en
el dashboard live, reemplazar claves por las live correspondientes, configurar
el endpoint del webhook en el dashboard de Stripe (en vez de `stripe listen`),
y revisar terminos fiscales/legales antes de cobrar.

## Deploy Backend en Render

Si Render no despliega automaticamente despues de un push, crear un **Deploy Hook** en Render y guardarlo en GitHub:

1. Render -> `ai-sentinel-backend` -> Settings -> Deploy Hook -> Create Deploy Hook.
2. GitHub -> repo `ai-sentinel` -> Settings -> Secrets and variables -> Actions -> New repository secret.
3. Nombre del secret:

```text
RENDER_DEPLOY_HOOK_URL
```

4. Valor: la URL del Deploy Hook de Render.
5. Ejecutar el workflow **Deploy Backend to Render** desde GitHub Actions o hacer push a `main`.

Para proteger endpoints de analisis, chat y dashboard con JWT, configurar:

```env
REQUIRE_AUTH_FOR_ANALYSIS=true
```

Puedes revisar que integraciones quedaron configuradas en:

```bash
curl http://localhost:8000/api/v1/integrations/status
```

## Motor de Riesgo

Puntuacion de 0 a 100:
- **0-24 (Bajo):** Seguro
- **25-49 (Medio):** Precaucion, hallazgos menores
- **50-74 (Alto):** Sospechoso, no interactuar
- **75-100 (Critico):** Ataque confirmado o intervencion de red

Formula:
```
Score = (0.30 * URL) + (0.25 * Contenido) + (0.20 * Cabeceras) + (0.25 * Red)
```

## Soporte

- **Web:** https://guardiaflow.com
- **Email:** soporte@guardiaflow.com
