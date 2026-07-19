@echo off
REM =============================================================================
REM EAIP Run Script (Windows)
REM Auto-checks Azure CLI login, activates virtual environment, and runs pipeline.
REM
REM Usage:
REM   run.bat --scan-subscription --subscription-ids YOUR-SUB-ID
REM   run.bat --full
REM   run.bat --help
REM =============================================================================

REM --- 1. Check Azure CLI Installation & Login status ---
where az >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Azure CLI (az) is not installed on the system.
    echo         Please download and install it from: https://aka.ms/installazurecliwindows
    echo.
    pause
    exit /b 1
)

REM Read .env file to extract EAIP_TENANT_ID (if present)
set TENANT_ID=
if exist .env (
    for /f "usebackq tokens=1,2 delims==" %%i in (".env") do (
        if "%%i"=="EAIP_TENANT_ID" set TENANT_ID=%%j
    )
)

REM Check if logged into Azure CLI
az account show >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] No active Azure CLI session found. Starting automatic login...
    if not "%TENANT_ID%"=="" (
        echo [INFO] Executing: az login --tenant %TENANT_ID%
        az login --tenant %TENANT_ID%
    ) else (
        echo [INFO] Executing: az login
        az login
    )
)

REM --- 2. Check Virtual Environment ---
set VENV_DIR=.venv

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at %VENV_DIR%
    echo         Run setup.bat first to create it.
    echo.
    pause
    exit /b 1
)

REM --- 3. Run Pipeline ---
call %VENV_DIR%\Scripts\activate.bat
python -m src.orchestrator.pipeline %*
deactivate
