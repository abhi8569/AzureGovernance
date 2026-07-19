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

# 4. Copy / Update .env if needed
if [ ! -f ".env" ]; then
    echo "[4/4] Creating .env from template..."
    cp .env.example .env
    echo "  → Created .env. Please edit it with your EAIP_TENANT_ID."
else
    echo "[4/4] .env already exists — checking for missing settings..."
    UPDATED=0
    if ! grep -q "EAIP_EXTRACT_SHAREPOINT" .env; then
        echo "" >> .env
        echo "# --- Feature Flags added by setup update ---" >> .env
        echo "EAIP_EXTRACT_SHAREPOINT=false" >> .env
        echo "EAIP_EXTRACT_TEAMS=false" >> .env
        echo "  → Appended new SharePoint and Teams feature flags to .env"
        UPDATED=1
    fi
    if ! grep -q "EAIP_RESOURCE_GROUPS" .env; then
        echo "" >> .env
        echo "# --- Resource Group Scoping added by setup update ---" >> .env
        echo "EAIP_RESOURCE_GROUPS=[]" >> .env
        echo "  → Appended new EAIP_RESOURCE_GROUPS setting to .env"
        UPDATED=1
    fi
    if [ "$UPDATED" -eq 0 ]; then
        echo "  → All settings up to date."
    fi
fi

echo ""
echo "====================================="
echo " Setup complete!"
echo "====================================="
echo ""
echo " Run tests:           ./run.sh --help (or tests using pytest)"
echo " Run scan:            ./run.sh --scan-subscription --subscription-ids YOUR-SUB-ID"
echo ""
