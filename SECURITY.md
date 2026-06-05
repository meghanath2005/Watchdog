# Security Policy

PC Usage Watchdog is a local diagnostic utility. It does not upload telemetry,
process lists, logs, reports, or command lines anywhere.

## Reporting Issues

If you find a security issue, open a private advisory or contact the maintainer
before posting exploit details publicly.

## Scope

Relevant security issues include:

- Incorrectly executing untrusted process command lines.
- Leaking logs or reports outside the local machine.
- Unsafe process termination behavior.
- Privilege escalation caused by launchers or cleanup scripts.

## Notes

Administrator mode is optional and is used only to improve Windows process-start
event visibility and process inspection. The app does not auto-kill processes.
