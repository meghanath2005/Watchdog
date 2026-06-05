import csv
import json
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import psutil

from pc_usage_watchdog.paths import data_root

BASE_DIR = data_root()
REPORT_DIR = BASE_DIR / "reports"
WATCHDOG_LOG = BASE_DIR / "logs" / "process_events.jsonl"

SCRIPT_TOOLS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "conhost.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "schtasks.exe",
    "wmic.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "python.exe",
    "pythonw.exe",
    "node.exe",
}

CORE_NAMES = {
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "winlogon.exe",
    "dwm.exe",
    "explorer.exe",
    "memory compression",
    "memcompression",
}

SUSPICIOUS_COMMAND_MARKERS = [
    " -enc",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "iex ",
    " -windowstyle hidden",
    " bypass",
    "\\temp\\",
    "\\appdata\\local\\temp\\",
]


def run(args, timeout=30):
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=creationflags,
        )
    except Exception as exc:
        return subprocess.CompletedProcess(args, 1, "", str(exc))


def ps_json(command, timeout=30):
    result = run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        timeout=timeout,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return data
    return [data]


def lower(value):
    return str(value or "").lower()


def normalized_path_text(value):
    return lower(value).strip().strip('"')


def user_writable(path):
    text = normalized_path_text(path)
    return any(
        marker in text
        for marker in [
            "\\appdata\\",
            "\\temp\\",
            "\\downloads\\",
            "\\desktop\\",
            "\\documents\\",
            "\\users\\public\\",
            "\\programdata\\",
        ]
    )


def systemish(path):
    text = normalized_path_text(path)
    if text.startswith(r"c:\programdata\microsoft\windows defender\platform\\") or text.startswith(
        r"c:\programdata\microsoft\windows defender\platform"
    ):
        return True
    roots = [
        lower(os.environ.get("WINDIR", r"C:\Windows")),
        lower(os.environ.get("ProgramFiles", r"C:\Program Files")),
        lower(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        r"c:\program files\windowsapps",
    ]
    return any(text.startswith(root) for root in roots if root)


def reasons_for(name, path, command, mem_mb=0, cpu_percent=0, age_sec=0):
    reasons = []
    score = 0
    lname = lower(name)
    lcmd = lower(command)
    lpath = lower(path)

    if lname in CORE_NAMES:
        return 0, ["Windows core or shell process"]
    if "\\openai\\codex\\bin\\" in lpath or "\\openai\\codex\\bin\\" in lcmd:
        return 0, ["OpenAI Codex local helper"]
    if "\\pc-usage-watchdog\\" in lcmd or "\\pc-usage-watchdog\\" in lpath:
        return 0, ["This audit/watchdog tooling"]
    if ("codex" in lcmd and "encodedcommand" in lcmd) or "rust command-safety layer" in lcmd:
        return 0, ["Codex helper process"]
    if cpu_percent >= 35:
        score += 35
        reasons.append(f"high CPU now ({cpu_percent:.0f}%)")
    elif cpu_percent >= 15:
        score += 15
        reasons.append(f"moderate CPU now ({cpu_percent:.0f}%)")
    if mem_mb >= 1000:
        score += 25
        reasons.append(f"high RAM ({mem_mb:.0f} MB)")
    elif mem_mb >= 250:
        score += 10
        reasons.append(f"notable RAM ({mem_mb:.0f} MB)")
    if lname in SCRIPT_TOOLS:
        score += 20
        reasons.append("console/script/admin tool")
    if path and user_writable(path) and not systemish(path):
        score += 25
        reasons.append("runs from user-writable path")
    if any(marker in lcmd or marker in lpath for marker in SUSPICIOUS_COMMAND_MARKERS):
        score += 30
        reasons.append("suspicious command pattern/path")
    if age_sec > 6 * 3600 and mem_mb >= 200:
        score += 8
        reasons.append("long-running memory user")
    return score, reasons or ["no obvious issue"]


def collect_processes():
    rows = []
    psutil.cpu_percent(interval=None)
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except Exception:
            pass
    time.sleep(0.6)

    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "username", "exe", "cmdline", "create_time", "memory_info", "status"]
    ):
        try:
            info = proc.info
            mem = info.get("memory_info")
            age = time.time() - float(info.get("create_time") or time.time())
            cmd = " ".join(info.get("cmdline") or [])
            row = {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name") or "",
                "user": info.get("username") or "",
                "exe": info.get("exe") or "",
                "command": cmd,
                "created": datetime.fromtimestamp(info.get("create_time") or time.time()).strftime("%Y-%m-%d %H:%M:%S"),
                "age_seconds": round(age, 1),
                "ram_mb": round((mem.rss if mem else 0) / (1024 * 1024), 1),
                "cpu_percent": round(proc.cpu_percent(interval=None), 1),
                "status": info.get("status") or "",
            }
            row["score"], row["reasons"] = reasons_for(
                row["name"], row["exe"], row["command"], row["ram_mb"], row["cpu_percent"], age
            )
            rows.append(row)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    by_pid = {row["pid"]: row for row in rows}
    for row in rows:
        parent = by_pid.get(row.get("ppid"))
        if (
            lower(row["name"]) == "powershell.exe"
            and "encodedcommand" in lower(row["command"])
            and parent
            and "codex" in lower(parent.get("name"))
        ):
            row["score"] = 0
            row["reasons"] = ["Codex PowerShell helper"]

    rows.sort(key=lambda r: (r["score"], r["ram_mb"]), reverse=True)
    return rows


def collect_startup():
    command = (
        "Get-CimInstance Win32_StartupCommand | "
        "Select-Object Name,Command,Location,User | ConvertTo-Json -Depth 4"
    )
    rows = ps_json(command)
    out = []
    for row in rows:
        cmd = row.get("Command", "")
        score, reasons = reasons_for(row.get("Name", ""), cmd, cmd)
        out.append({**row, "score": score, "reasons": reasons})
    out.sort(key=lambda r: r.get("score", 0), reverse=True)
    return out


def collect_tasks():
    result = run(["schtasks.exe", "/query", "/fo", "csv", "/v"], timeout=30)
    if result.returncode != 0:
        return [{"error": result.stderr.strip()}]
    rows = []
    for row in csv.DictReader(result.stdout.splitlines()):
        command = row.get("Task To Run") or ""
        name = row.get("TaskName") or ""
        status = row.get("Status") or ""
        schedule = row.get("Schedule Type") or ""
        if not command or command.upper() == "N/A":
            continue
        score, reasons = reasons_for(name, command, command)
        if lower(status) != "disabled" and score >= 20:
            rows.append(
                {
                    "name": name,
                    "status": status,
                    "schedule": schedule,
                    "last_run": row.get("Last Run Time") or "",
                    "next_run": row.get("Next Run Time") or "",
                    "command": command,
                    "score": score,
                    "reasons": reasons,
                }
            )
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows


def collect_services():
    command = (
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,State,StartMode,StartName,PathName | ConvertTo-Json -Depth 4"
    )
    rows = []
    for row in ps_json(command, timeout=30):
        path = row.get("PathName", "")
        score, reasons = reasons_for(row.get("Name", ""), path, path)
        if score >= 20:
            rows.append({**row, "score": score, "reasons": reasons})
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows


def collect_watchdog_events():
    if not WATCHDOG_LOG.exists():
        return {"summary": {}, "recent": []}
    events = []
    with WATCHDOG_LOG.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    recent = events[-300:]
    counts = Counter(lower(e.get("name")) for e in recent if e.get("name"))
    flagged = []
    for event in recent:
        name = event.get("name") or ""
        command = event.get("command_line") or event.get("executable_path") or ""
        score, reasons = reasons_for(name, event.get("executable_path", ""), command)
        if score >= 20 or lower(name) in SCRIPT_TOOLS or event.get("source") == "watcher-error":
            flagged.append({**event, "score": score, "reasons": reasons})
    return {"summary": dict(counts.most_common(20)), "recent": flagged[-80:]}


def collect_defender_events():
    command = (
        "$since=(Get-Date).AddDays(-14); "
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$since} "
        "-MaxEvents 80 -ErrorAction SilentlyContinue | "
        "Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json -Depth 4"
    )
    rows = ps_json(command, timeout=30)
    interesting = []
    for row in rows:
        msg = lower(row.get("Message", ""))
        if any(marker in msg for marker in ["threat", "malware", "detected", "remediation", "quarantine", "blocked"]):
            interesting.append(row)
    return interesting[:40]


def explorer_details(processes):
    explorers = [p for p in processes if lower(p["name"]) == "explorer.exe"]
    signature = ps_json(
        "Get-AuthenticodeSignature C:\\Windows\\explorer.exe | "
        "Select-Object Status,StatusMessage,@{Name='Subject';Expression={$_.SignerCertificate.Subject}},Path | "
        "ConvertTo-Json -Depth 3",
        timeout=15,
    )
    return {"processes": explorers, "signature": signature}


def write_markdown(report, path):
    lines = []
    lines.append(f"# PC Mole Audit - {report['generated_at']}")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append(report["verdict"])
    lines.append("")

    lines.append("## Explorer")
    exp = report["explorer"]
    for p in exp["processes"]:
        lines.append(f"- `explorer.exe` PID `{p['pid']}` uses `{p['ram_mb']} MB`, path `{p['exe']}`, started `{p['created']}`.")
    if exp["signature"]:
        sig = exp["signature"][0]
        lines.append(f"- Signature: `{sig.get('StatusMessage')}`; signer `{sig.get('Subject')}`.")
    lines.append("")

    lines.append("## Highest RAM Processes")
    for p in sorted(report["processes"], key=lambda r: r["ram_mb"], reverse=True)[:20]:
        lines.append(f"- `{p['name']}` PID `{p['pid']}` RAM `{p['ram_mb']} MB`, CPU `{p['cpu_percent']}%`, path `{p['exe']}`")
    lines.append("")

    lines.append("## Processes To Review")
    review = [p for p in report["processes"] if p["score"] >= 20]
    if review:
        for p in review[:40]:
            lines.append(f"- Score `{p['score']}` `{p['name']}` PID `{p['pid']}`: {', '.join(p['reasons'])}; path `{p['exe']}`; command `{p['command']}`")
    else:
        lines.append("- No current process crossed the review threshold.")
    lines.append("")

    lines.append("## Startup Entries")
    for item in report["startup"][:40]:
        lines.append(f"- Score `{item.get('score', 0)}` `{item.get('Name')}` from `{item.get('Location')}`: {', '.join(item.get('reasons', []))}; command `{item.get('Command')}`")
    lines.append("")

    lines.append("## Scheduled Tasks To Review")
    if report["scheduled_tasks"]:
        for item in report["scheduled_tasks"][:60]:
            lines.append(f"- Score `{item.get('score', 0)}` `{item.get('name')}` `{item.get('status')}` `{item.get('schedule')}`: {', '.join(item.get('reasons', []))}; command `{item.get('command')}`")
    else:
        lines.append("- No enabled scheduled task crossed the review threshold.")
    lines.append("")

    lines.append("## Services To Review")
    if report["services"]:
        for item in report["services"][:50]:
            lines.append(f"- Score `{item.get('score', 0)}` `{item.get('Name')}` `{item.get('State')}` `{item.get('StartMode')}`: {', '.join(item.get('reasons', []))}; path `{item.get('PathName')}`")
    else:
        lines.append("- No service crossed the review threshold.")
    lines.append("")

    lines.append("## Watchdog Process-Start Events")
    events = report["watchdog_events"]
    if events["summary"]:
        lines.append("- Most common recent event names: " + ", ".join(f"`{k}`={v}" for k, v in events["summary"].items()))
    if events["recent"]:
        for event in events["recent"][-30:]:
            lines.append(f"- `{event.get('time')}` `{event.get('name')}` source `{event.get('source')}`: {', '.join(event.get('reasons', []))}; command `{event.get('command_line')}`")
    else:
        lines.append("- No Watchdog log events found yet.")
    lines.append("")

    lines.append("## Defender Events")
    if report["defender_events"]:
        for item in report["defender_events"][:20]:
            message = " ".join(str(item.get("Message", "")).split())
            lines.append(f"- `{item.get('TimeCreated')}` event `{item.get('Id')}` `{message[:500]}`")
    else:
        lines.append("- No recent Defender threat/remediation events were returned to this non-admin audit.")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    processes = collect_processes()
    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "processes": processes,
        "startup": collect_startup(),
        "scheduled_tasks": collect_tasks(),
        "services": collect_services(),
        "watchdog_events": collect_watchdog_events(),
        "defender_events": collect_defender_events(),
    }
    report["explorer"] = explorer_details(processes)

    suspicious_processes = [p for p in processes if p["score"] >= 50]
    suspicious_tasks = [t for t in report["scheduled_tasks"] if t.get("score", 0) >= 50]
    suspicious_services = [s for s in report["services"] if s.get("score", 0) >= 50]
    if suspicious_processes or suspicious_tasks or suspicious_services:
        report["verdict"] = "High-priority review items exist. These are not confirmed malware, but they need manual inspection."
    else:
        report["verdict"] = "No obvious active malware-style process, startup entry, scheduled task, or service was identified by this non-admin audit. Review the flagged background apps for bloat and run the Watchdog as Administrator to catch one-second command flashes reliably."

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = REPORT_DIR / f"audit-{stamp}.json"
    md_path = REPORT_DIR / f"audit-{stamp}.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    write_markdown(report, md_path)
    print(str(md_path))
    print(str(json_path))


if __name__ == "__main__":
    sys.exit(main())
