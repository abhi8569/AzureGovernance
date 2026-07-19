@echo off
REM =============================================================================
REM EAIP Run Script (Windows)
REM Auto-activates the virtual environment and runs the pipeline.
REM
REM Usage:
REM   run.bat --scan-subscription --subscription-ids YOUR-SUB-ID
REM   run.bat --full
REM   run.bat --help
REM =============================================================================

set VENV_DIR=.venv

REM Check if venv exists
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at %VENV_DIR%
    echo         Run setup.bat first to create it.
    echo.
    pause
    exit /b 1
)

REM Activate venv and run pipeline with all passed arguments
call %VENV_DIR%\Scripts\activate.bat
python -m src.orchestrator.pipeline %*

REM Deactivate after run
deactivate
