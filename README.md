# AI-Sentinel - Ciberseguridad Avanzada con IA

Aplicacion de ciberseguridad potente con deteccion de phishing, intervencion de datos por IA (AiTM), QRishing, Deepfakes y Threat Intelligence en tiempo real.

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
FRONTEND_URL=https://frontend-kappa-wheat-28.vercel.app
```

En Google Cloud, agregar el mismo valor de `GOOGLE_OAUTH_REDIRECT_URI` en **Authorized redirect URIs**.

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
