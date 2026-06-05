@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\pythonw.exe" (
  call install.bat
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$startup=[Environment]::GetFolderPath('Startup'); $path=Join-Path $startup 'PC Usage Watchdog Startup Logger.lnk'; $shell=New-Object -ComObject WScript.Shell; $s=$shell.CreateShortcut($path); $s.TargetPath='%~dp0.venv\Scripts\pythonw.exe'; $s.Arguments='-m pc_usage_watchdog'; $s.WorkingDirectory='%~dp0'; $s.IconLocation='$env:SystemRoot\System32\Taskmgr.exe'; $s.Description='Start PC Usage Watchdog after login and keep process-start logs.'; $s.Save(); Write-Host $path"
echo.
echo Startup logging enabled with a Startup-folder shortcut.
echo The app will start after your next Windows login and write logs to:
echo   %~dp0logs\process_events.jsonl
echo.
echo Note: this normal startup launcher may not get Administrator-only WMI events.
echo For best one-second CMD flash capture, run "PC Usage Watchdog Admin" after login.
pause
