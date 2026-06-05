@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  call install.bat
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~dp0.venv\Scripts\pythonw.exe' -ArgumentList '-m pc_usage_watchdog' -WorkingDirectory '%~dp0' -Verb RunAs"
