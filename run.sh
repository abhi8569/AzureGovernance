#!/usr/bin/env bash
# =============================================================================
# EAIP Run Script (Linux / macOS / Git Bash)
# Auto-checks Azure CLI login, activates virtual environment, and runs pipeline.
#
# Usage:
#   ./run.sh --scan-subscription --subscription-ids YOUR-SUB-ID
#   ./run.sh --full
#   ./run.sh --help
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- 1. Check Azure CLI Installation & Login status ---
if ! command -v az &> /dev/null; then
    echo "[ERROR] Azure CLI (az) is not installed on the system."
    echo "        Please install it from: https://aka.ms/InstallAzureCli"
    exit 1
fi

# Read .env file to extract EAIP_TENANT_ID (if present)
TENANT_ID=""
if [ -f .env ]; then
    TENANT_ID=$(grep -E "^EAIP_TENANT_ID=" .env | cut -d'=' -f2- | tr -d '"' | tr -d "'" | tr -d '[:space:]')
fi

# Check if logged into Azure CLI
if ! az account show &> /dev/null; then
    echo "[INFO] No active Azure CLI session found. Starting automatic login..."
    if [ -n "$TENANT_ID" ]; then
        echo "[INFO] Executing: az login --tenant $TENANT_ID"
        az login --tenant "$TENANT_ID"
    else
        echo "[INFO] Executing: az login"
        az login
    fi
fi

# --- 2. Check Virtual Environment ---
VENV_DIR=".venv"

if [ ! -f "$VENV_DIR/bin/python" ] && [ ! -f "$VENV_DIR/Scripts/python.exe" ]; then
    echo "[ERROR] Virtual environment not found at $VENV_DIR"
    echo "        Run 'bash setup.sh' first to create it."
    exit 1
fi

# Determine activation path (cross-platform bash support)
if [ -f "$VENV_DIR/bin/activate" ]; then
    source "$VENV_DIR/bin/activate"
elif [ -f "$VENV_DIR/Scripts/activate" ]; then
    source "$VENV_DIR/Scripts/activate"
fi

# --- 3. Run Pipeline ---
python -m src.orchestrator.pipeline "$@"
deactivate
