# Privacy

PC Usage Watchdog is local-only.

It can collect:

- Process names, PIDs, executable paths, command lines, users, CPU usage, RAM usage, and start times.
- Startup entries, scheduled tasks, and services.
- Windows Defender status and selected event summaries when audit scripts are run.

It does not:

- Upload data.
- Phone home.
- Send reports to GitHub.
- Persist data outside the project `logs` and `reports` folders.

Reports may contain sensitive local paths and command lines. Do not publish
generated reports unless you have reviewed and sanitized them.
