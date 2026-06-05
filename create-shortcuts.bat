@echo off
setlocal
cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0create-shortcuts.ps1"
echo.
echo To pin it: right-click "PC Usage Watchdog" on your Desktop, then choose "Pin to taskbar".
pause
