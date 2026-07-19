@echo off
REM =============================================================================
REM EAIP Test Runner (Windows)
REM Auto-activates the virtual environment and runs pytest.
REM
REM Usage:
REM   test.bat              (run all tests)
REM   test.bat -k "test_sql" (run specific tests)
REM =============================================================================

set VENV_DIR=.venv

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found. Run setup.bat first.
    pause
    exit /b 1
)

call %VENV_DIR%\Scripts\activate.bat
python -m pytest tests/ %*
deactivate
