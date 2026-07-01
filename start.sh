#!/bin/bash
# AI-Sentinel - Script de arranque local
# Ejecuta backend y frontend en paralelo

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "========================================="
echo "  AI-Sentinel - Ciberseguridad Avanzada"
echo "========================================="
echo ""

# Backend
echo "[1/2] Iniciando Backend (FastAPI)..."
cd "$ROOT_DIR/backend"

if [ ! -d "venv" ]; then
    echo "  -> Creando entorno virtual..."
    python3 -m venv venv
fi

source venv/bin/activate
echo "  -> Instalando dependencias..."
pip install -q -r requirements.txt 2>/dev/null

echo "  -> Backend corriendo en http://localhost:8000"
echo "  -> Docs API en http://localhost:8000/docs"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# Frontend
echo ""
echo "[2/2] Iniciando Frontend (Next.js)..."
cd "$ROOT_DIR/frontend"

echo "  -> Instalando dependencias..."
npm install --silent 2>/dev/null

echo "  -> Frontend corriendo en http://localhost:3000"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "========================================="
echo "  AI-Sentinel esta corriendo!"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo "========================================="
echo ""
echo "Presiona Ctrl+C para detener ambos servicios"

cleanup() {
    echo ""
    echo "Deteniendo servicios..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

wait
