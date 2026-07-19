#!/usr/bin/env bash
# =============================================================================
# EAIP Run Script (Linux / macOS / Git Bash)
# Auto-activates virtual environment and runs pipeline.
# Automatic 'az login' check is handled inside Python.
#
# Usage:
#   ./run.sh --scan-subscription --subscription-ids YOUR-SUB-ID
#   ./run.sh --full
#   ./run.sh --help
# =============================================================================
set -e

VENV_DIR=".venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "$VENV_DIR/bin/python" ] && [ ! -f "$VENV_DIR/Scripts/python.exe" ]; then
    echo "[ERROR] Virtual environment not found at $VENV_DIR"
    echo "        Run 'bash setup.sh' first to create it."
    exit 1
fi

if [ -f "$VENV_DIR/bin/activate" ]; then
    source "$VENV_DIR/bin/activate"
elif [ -f "$VENV_DIR/Scripts/activate" ]; then
    source "$VENV_DIR/Scripts/activate"
fi

python -m src.orchestrator.pipeline "$@"
deactivate
