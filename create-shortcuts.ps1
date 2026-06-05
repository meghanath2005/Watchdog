param(
  [switch]$AdminOnly
)

$ErrorActionPreference = "Stop"

$AppDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppName = "PC Usage Watchdog"
$Pythonw = Join-Path $AppDir ".venv\Scripts\pythonw.exe"
$ModuleArgs = "-m pc_usage_watchdog"
$Icon = "$env:SystemRoot\System32\Taskmgr.exe"

if (-not (Test-Path $Pythonw)) {
  & (Join-Path $AppDir "install.bat")
}

$Desktop = [Environment]::GetFolderPath("Desktop")
$Programs = [Environment]::GetFolderPath("Programs")
$StartMenuFolder = Join-Path $Programs $AppName
New-Item -ItemType Directory -Force -Path $StartMenuFolder | Out-Null

$Shell = New-Object -ComObject WScript.Shell

function New-AppShortcut {
  param(
    [string]$Path,
    [string]$Target,
    [string]$Arguments,
    [string]$Description
  )

  $Shortcut = $Shell.CreateShortcut($Path)
  $Shortcut.TargetPath = $Target
  $Shortcut.Arguments = $Arguments
  $Shortcut.WorkingDirectory = $AppDir
  $Shortcut.IconLocation = $Icon
  $Shortcut.Description = $Description
  $Shortcut.Save()
}

if (-not $AdminOnly) {
  New-AppShortcut `
    -Path (Join-Path $Desktop "$AppName.lnk") `
    -Target $Pythonw `
    -Arguments $ModuleArgs `
    -Description "Monitor CPU, RAM, background processes, startup apps, and process flashes."

  New-AppShortcut `
    -Path (Join-Path $StartMenuFolder "$AppName.lnk") `
    -Target $Pythonw `
    -Arguments $ModuleArgs `
    -Description "Monitor CPU, RAM, background processes, startup apps, and process flashes."
}

$AdminCommand = "Start-Process -FilePath `"$Pythonw`" -ArgumentList `"$ModuleArgs`" -WorkingDirectory `"$AppDir`" -Verb RunAs"
New-AppShortcut `
  -Path (Join-Path $Desktop "$AppName Admin.lnk") `
  -Target "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -Arguments "-NoProfile -ExecutionPolicy Bypass -Command $AdminCommand" `
  -Description "Run PC Usage Watchdog as Administrator for best short-lived process capture."

New-AppShortcut `
  -Path (Join-Path $StartMenuFolder "$AppName Admin.lnk") `
  -Target "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -Arguments "-NoProfile -ExecutionPolicy Bypass -Command $AdminCommand" `
  -Description "Run PC Usage Watchdog as Administrator for best short-lived process capture."

Write-Host "Created shortcuts:"
Write-Host "  $Desktop\$AppName.lnk"
Write-Host "  $Desktop\$AppName Admin.lnk"
Write-Host "  $StartMenuFolder"
Write-Host ""
Write-Host "To pin it: right-click the Desktop or Start Menu shortcut, then choose Pin to taskbar."
