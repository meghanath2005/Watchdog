# Deployment

## Option 1: Python Install

Install Python 3.10+ on Windows, then run:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install .
pc-usage-watchdog
```

## Option 2: Double-Click Launchers

Use the included batch files:

- `install.bat` creates `.venv` and installs dependencies.
- `run.bat` launches the desktop app.
- `run-admin.bat` launches the desktop app elevated.
- `create-shortcuts.bat` creates Desktop and Start Menu shortcuts.
- `enable-startup-logging.bat` starts the app automatically after login.

## Option 3: Windows EXE

Install development dependencies and run:

```powershell
.\scripts\build_windows_exe.ps1
```

The executable will be placed under `dist\`.

## Logs And Reports

Source checkout launchers write runtime artifacts inside the project folder:

- `logs\process_events.jsonl`
- `reports\*.md`
- `reports\*.json`

Installed packages and frozen EXE builds write to:

```text
%LOCALAPPDATA%\PCUsageWatchdog\
```

Use `PC_USAGE_WATCHDOG_HOME` to override this location.
