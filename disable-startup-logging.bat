@echo off
setlocal

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$startup=[Environment]::GetFolderPath('Startup'); $path=Join-Path $startup 'PC Usage Watchdog Startup Logger.lnk'; if (Test-Path $path) { Remove-Item -LiteralPath $path -Force; Write-Host \"Removed $path\" }"
schtasks.exe /Delete /F /TN "PC Usage Watchdog Startup Logger" >nul 2>nul
echo.
echo Startup logging disabled.
pause
