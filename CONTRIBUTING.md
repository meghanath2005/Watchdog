# Contributing

## Local Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .[dev]
```

## Run

```powershell
.\.venv\Scripts\python.exe -m pc_usage_watchdog
```

## Test

```powershell
.\.venv\Scripts\python.exe -m pytest
```

## Guidelines

- Do not commit generated logs, reports, virtual environments, or local machine data.
- Keep Windows cleanup scripts scoped to explicit targets.
- Avoid auto-killing or auto-disabling processes without user confirmation.
