$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

if (-not (Test-Path ".venv\Scripts\python.exe")) {
  python -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

.\.venv\Scripts\python.exe -m PyInstaller `
  --name "PCUsageWatchdog" `
  --windowed `
  --onefile `
  --clean `
  --collect-submodules pc_usage_watchdog `
  pc_usage_watchdog\__main__.py

Write-Host "Built executable under dist\PCUsageWatchdog.exe"
