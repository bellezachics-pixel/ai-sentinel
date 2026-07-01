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

## API Keys (Opcionales)

Crear archivo `.env` en la raiz del backend:

```env
VIRUSTOTAL_API_KEY=tu_api_key
URLSCAN_API_KEY=tu_api_key
ABUSEIPDB_API_KEY=tu_api_key
OPENAI_API_KEY=tu_api_key
```

La app funciona sin API keys con capacidades reducidas (analisis local solamente).

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
