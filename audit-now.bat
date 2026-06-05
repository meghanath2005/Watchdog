@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  call install.bat
)

".venv\Scripts\python.exe" -m pc_usage_watchdog.audit
echo.
echo Report saved under "%~dp0reports".
pause
