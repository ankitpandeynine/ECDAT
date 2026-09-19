#!/usr/bin/env bash
# =====================================================================
#  ECDAT: Enterprise Cryptographic Discovery & Analysis Tool (SIH26164)
#  Cross-Platform Startup Script for Linux & macOS
# =====================================================================
set -e

echo "====================================================================="
echo " ECDAT: Enterprise Cryptographic Discovery & Analysis Tool (SIH26164)"
echo " National Technical Research Organisation (NTRO) Prototype"
echo "====================================================================="
echo ""

# 1. Detect Python command
if command -v python3 >/dev/null 2>&1; then
    PY_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PY_CMD="python"
else
    echo "[!] Error: Python is not installed. Please install Python 3.10+"
    exit 1
fi

# 2. Detect Node.js / npm
if ! command -v npm >/dev/null 2>&1; then
    echo "[!] Error: npm is not installed. Please install Node.js 18+"
    exit 1
fi

# 3. Setup Virtual Environment
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    $PY_CMD -m venv .venv
fi

# Ensure pip is installed inside .venv
if [ ! -f ".venv/bin/pip" ]; then
    echo "[*] Bootstrapping pip in virtual environment..."
    .venv/bin/python -m ensurepip --default-pip || true
fi

echo "[*] Installing backend dependencies..."
.venv/bin/python -m pip install --upgrade pip -q
.venv/bin/python -m pip install -r backend/requirements.txt -q

# 4. Start Backend
echo "[*] Launching FastAPI Backend on http://127.0.0.1:8000..."
cd backend
PYTHONPATH=. ../.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
cd ..

# 5. Install & Start Frontend
echo "[*] Installing frontend dependencies..."
cd frontend
npm install --silent

echo "[*] Launching Next.js Frontend on http://localhost:3000..."
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "====================================================================="
echo " [+] ECDAT is live!"
echo "     - Frontend Dashboard: http://localhost:3000"
echo "     - Backend API Docs:   http://127.0.0.1:8000/docs"
echo "====================================================================="
echo " Press [Ctrl+C] to stop all services..."
echo ""

# Ensure child processes terminate gracefully on Ctrl+C or script exit
trap "echo '[*] Shutting down ECDAT services...'; kill -TERM $BACKEND_PID $FRONTEND_PID 2>/dev/null || true; exit 0" SIGINT SIGTERM EXIT
wait
