# PC Usage Watchdog

Windows desktop utility for monitoring CPU/RAM usage, reviewing background
processes, catching short-lived command windows, and auditing startup entries,
scheduled tasks, and services.

The app is local-only. It does not upload telemetry or reports.

## Features

- Live CPU and RAM overview.
- Process table sorted by review score, CPU, RAM, age, user, path, and reason.
- Flags common review targets: high CPU, high RAM, script/admin tools, user-writable executable paths, and suspicious command-line patterns.
- Logs process-start events to help catch black `cmd.exe` / PowerShell flashes.
- Startup registry and Startup-folder review.
- Scheduled-task review, including commands that can launch background helpers.
- Safe manual process termination with confirmation and Windows-core process guardrails.
- Repeatable audit reports and 2-minute clean reports.
- Desktop, Start Menu, startup-logging, and admin launchers for Windows users.

## Screens

The main app has four tabs:

- `Processes`: current CPU/RAM/process review.
- `CMD flashes and starts`: process-start event log.
- `Startup/background`: startup entries and scheduled tasks.
- `Actions`: recommended workflow.

## Quick Start

Requires Windows and Python 3.10+.

Double-click:

```bat
install.bat
```

Then start normally:

```bat
run.bat
```

For better visibility into one-second command windows, run elevated:

```bat
run-admin.bat
```

## Shortcuts And Auto Start

Create Desktop and Start Menu shortcuts:

```bat
create-shortcuts.bat
```

Start automatically after Windows login:

```bat
enable-startup-logging.bat
```

Remove auto-start:

```bat
disable-startup-logging.bat
```

## Reports

One-shot audit:

```bat
audit-now.bat
```

Two-minute clean report:

```bat
clean-report-now.bat
```

When running from this source checkout, reports are written to:

```text
reports\
```

When running from this source checkout, process-start logs are written to:

```text
logs\process_events.jsonl
```

Generated logs and reports are intentionally excluded from git because they can
contain local paths, command lines, usernames, and other machine-specific data.

Installed package or EXE builds write runtime data under:

```text
%LOCALAPPDATA%\PCUsageWatchdog\
```

Set `PC_USAGE_WATCHDOG_HOME` to override the data directory.

## Developer Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .[dev]
.\.venv\Scripts\python.exe -m pytest
```

Run the app as a module:

```powershell
.\.venv\Scripts\python.exe -m pc_usage_watchdog
```

Build a Windows executable:

```powershell
.\scripts\build_windows_exe.ps1
```

## Important Notes

- A high review score is not proof of malware. It means “inspect this.”
- Microsoft Defender may show high CPU/RAM during scans.
- Administrator mode improves access to WMI process-start events and protected process details.
- The app does not auto-kill, auto-disable, or delete anything without explicit user action.

## Privacy

See [docs/PRIVACY.md](docs/PRIVACY.md).

## Deployment

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## License

MIT. See [LICENSE](LICENSE).
