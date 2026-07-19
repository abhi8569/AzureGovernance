@echo off
REM =============================================================================
REM EAIP Run Script (Windows)
REM Auto-activates virtual environment and runs pipeline.
REM Automatic 'az login' check is handled inside Python.
REM
REM Usage:
REM   run.bat --scan-subscription --subscription-ids YOUR-SUB-ID
REM   run.bat --full
REM   run.bat --help
REM =============================================================================

set VENV_DIR=.venv

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at %VENV_DIR%
    echo         Run setup.bat first to create it.
    echo.
    pause
    exit /b 1
)

call %VENV_DIR%\Scripts\activate.bat
python -m src.orchestrator.pipeline %*
deactivate
