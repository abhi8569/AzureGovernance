@echo off
REM =============================================================================
REM EAIP Setup Script (Windows)
REM Creates a virtual environment and installs all dependencies.
REM =============================================================================

set VENV_DIR=.venv

echo =====================================
echo  EAIP - Enterprise Access Intelligence Platform
echo  Setup Script (Windows)
echo =====================================
echo.

REM 1. Check Python
echo [1/4] Checking Python version...
python --version 2>nul
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.11+ from https://python.org
    exit /b 1
)

REM 2. Create venv
if exist "%VENV_DIR%\Scripts\python.exe" (
    echo [2/4] Virtual environment already exists at %VENV_DIR%
) else (
    echo [2/4] Creating virtual environment...
    python -m venv %VENV_DIR%
)

REM 3. Install dependencies
echo [3/4] Installing dependencies...
call %VENV_DIR%\Scripts\activate.bat
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

REM 4. Copy .env
if not exist ".env" (
    echo [4/4] Creating .env from template...
    copy .env.example .env >nul
    echo   -^> Edit .env with your EAIP_TENANT_ID and EAIP_CLIENT_ID
) else (
    echo [4/4] .env already exists - skipping
)

echo.
echo =====================================
echo  Setup complete!
echo =====================================
echo.
echo  Run tests:           test.bat
echo  Run scan:            run.bat --scan-subscription --subscription-ids YOUR-SUB-ID
echo.
pause
