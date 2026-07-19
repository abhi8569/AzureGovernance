#!/usr/bin/env bash
# =============================================================================
# EAIP Run Script (Linux / macOS / Git Bash)
# Auto-activates the virtual environment and runs the pipeline.
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

# Check if venv exists
if [ ! -f "$VENV_DIR/bin/python" ]; then
    echo "[ERROR] Virtual environment not found at $VENV_DIR"
    echo "        Run 'bash setup.sh' first to create it."
    exit 1
fi

# Activate venv and run pipeline with all passed arguments
source "$VENV_DIR/bin/activate"
python -m src.orchestrator.pipeline "$@"
deactivate
