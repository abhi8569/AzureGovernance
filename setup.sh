#!/usr/bin/env bash
# =============================================================================
# EAIP Setup Script (Linux / macOS / Git Bash)
# Creates a virtual environment and installs all dependencies.
# =============================================================================
set -e

VENV_DIR=".venv"
PYTHON="${PYTHON:-python3}"

echo "====================================="
echo " EAIP — Enterprise Access Intelligence Platform"
echo " Setup Script"
echo "====================================="
echo ""

# 1. Check Python version
echo "[1/4] Checking Python version..."
$PYTHON --version 2>/dev/null || { echo "ERROR: Python not found. Install Python 3.11+"; exit 1; }

# 2. Create virtual environment
if [ -d "$VENV_DIR" ]; then
    echo "[2/4] Virtual environment already exists at $VENV_DIR"
else
    echo "[2/4] Creating virtual environment..."
    $PYTHON -m venv "$VENV_DIR"
fi

# 3. Activate and install
echo "[3/4] Installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# 4. Copy .env if needed
if [ ! -f ".env" ]; then
    echo "[4/4] Creating .env from template..."
    cp .env.example .env
    echo "  → Edit .env with your EAIP_TENANT_ID and EAIP_CLIENT_ID"
else
    echo "[4/4] .env already exists — skipping"
fi

echo ""
echo "====================================="
echo " Setup complete!"
echo "====================================="
echo ""
echo " Activate the venv:   source .venv/bin/activate"
echo " Run tests:           python -m pytest tests/ -v"
echo " Run scan:            python -m src.orchestrator.pipeline --scan-subscription --subscription-ids YOUR-SUB-ID"
echo ""
