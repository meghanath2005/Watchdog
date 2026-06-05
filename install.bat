@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.10+ from https://www.python.org/downloads/windows/
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  python -m venv .venv
)

".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -e .

echo.
echo Install complete. Run run.bat to start PC Usage Watchdog.
pause
