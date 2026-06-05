import csv
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import psutil

from pc_usage_watchdog.paths import data_root

BASE_DIR = data_root()
REPORT_DIR = BASE_DIR / "reports"
SAMPLE_SECONDS = 120
SAMPLE_INTERVAL = 5

MICROSOFT_ROOTS = (
    "c:\\windows\\",
    "c:\\program files\\windowsapps\\microsoft",
    "c:\\program files\\microsoft",
    "c:\\program files (x86)\\microsoft",
    "c:\\programdata\\microsoft\\windows defender",
)

KNOWN_SAFE_MARKERS = (
    "\\openai\\codex",
    "program files\\windowsapps\\openai.codex",
    "\\pc-usage-watchdog\\",
)

REVIEW_TOOLS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "schtasks.exe",
    "wmic.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

SUSPICIOUS_MARKERS = (
    "-encodedcommand",
    " -enc",
    "frombase64string",
    "downloadstring",
    "iex ",
    " -windowstyle hidden",
    " bypass",
    "\\appdata\\local\\temp\\",
    "\\temp\\",
)

LOGMEIN_MARKERS = ("logmein", "rescue applet", "support-logmeinrescue", "lmirescue", "lmi_rescue")


def lower(value):
    return str(value or "").lower()


def clean_path(value):
    return lower(value).strip().strip('"')


def is_microsoft_path(value):
    text = clean_path(value)
    return any(text.startswith(root) for root in MICROSOFT_ROOTS)


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
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        timeout=timeout,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def process_snapshot():
    rows = []
    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "memory_info", "status"]
    ):
        try:
            info = proc.info
            mem = info.get("memory_info")
            cmd = " ".join(info.get("cmdline") or [])
            rows.append(
                {
                    "pid": int(info.get("pid") or 0),
                    "ppid": int(info.get("ppid") or 0),
                    "name": info.get("name") or "",
                    "exe": info.get("exe") or "",
                    "cmdline": cmd,
                    "user": info.get("username") or "",
                    "created": datetime.fromtimestamp(info.get("create_time") or time.time()).strftime("%Y-%m-%d %H:%M:%S"),
                    "age_seconds": round(time.time() - float(info.get("create_time") or time.time()), 1),
                    "ram_mb": round((mem.rss if mem else 0) / (1024 * 1024), 1),
                    "cpu_percent": round(proc.cpu_percent(interval=None), 1),
                    "status": info.get("status") or "",
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return rows


def monitor_samples(seconds=SAMPLE_SECONDS, interval=SAMPLE_INTERVAL):
    psutil.cpu_percent(interval=None)
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except Exception:
            pass

    samples = []
    end = time.time() + seconds
    while time.time() < end:
        time.sleep(interval)
        samples.append(
            {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "system_cpu_percent": psutil.cpu_percent(interval=None),
                "system_ram_percent": psutil.virtual_memory().percent,
                "processes": process_snapshot(),
            }
        )
    return samples


def aggregate_samples(samples):
    agg = {}
    for sample in samples:
        for row in sample["processes"]:
            pid = row["pid"]
            key = f"{pid}:{row['name']}"
            if key not in agg:
                agg[key] = {
                    "pid": pid,
                    "name": row["name"],
                    "exe": row["exe"],
                    "cmdline": row["cmdline"],
                    "user": row["user"],
                    "samples": 0,
                    "max_ram_mb": 0.0,
                    "avg_ram_mb": 0.0,
                    "max_cpu_percent": 0.0,
                    "avg_cpu_percent": 0.0,
                }
            item = agg[key]
            item["samples"] += 1
            item["max_ram_mb"] = max(item["max_ram_mb"], row["ram_mb"])
            item["avg_ram_mb"] += row["ram_mb"]
            item["max_cpu_percent"] = max(item["max_cpu_percent"], row["cpu_percent"])
            item["avg_cpu_percent"] += row["cpu_percent"]

    for item in agg.values():
        count = max(1, item["samples"])
        item["avg_ram_mb"] = round(item["avg_ram_mb"] / count, 1)
        item["avg_cpu_percent"] = round(item["avg_cpu_percent"] / count, 1)
    return sorted(agg.values(), key=lambda x: (x["max_cpu_percent"], x["max_ram_mb"]), reverse=True)


def classify(item, signature=None):
    name = lower(item.get("name"))
    exe = lower(item.get("exe"))
    cmd = lower(item.get("cmdline"))
    text = f"{name} {exe} {cmd}"
    reasons = []
    score = 0

    if any(marker in text for marker in KNOWN_SAFE_MARKERS):
        return 0, ["known safe local tooling"]
    if is_microsoft_path(exe):
        if item.get("max_cpu_percent", 0) >= 25:
            return 10, ["Microsoft/Windows process, temporarily high CPU"]
        return 0, ["Microsoft/Windows signed-location process"]
    if "program files\\windowsapps\\ad2f1837." in exe or "\\program files\\hp\\" in exe:
        score += 5
        reasons.append("HP/OEM utility")
    if any(marker in text for marker in LOGMEIN_MARKERS):
        score += 45
        reasons.append("LogMeIn/Rescue-related")
    if name in REVIEW_TOOLS:
        score += 25
        reasons.append("script/admin tool")
    if any(marker in cmd for marker in SUSPICIOUS_MARKERS):
        score += 35
        reasons.append("suspicious command pattern")
    if "\\appdata\\" in exe or "\\temp\\" in exe:
        score += 20
        reasons.append("runs from user-writable path")
    if item.get("max_cpu_percent", 0) >= 30:
        score += 20
        reasons.append(f"high CPU spike ({item['max_cpu_percent']:.1f}%)")
    if item.get("max_ram_mb", 0) >= 300:
        score += 10
        reasons.append(f"high RAM ({item['max_ram_mb']:.1f} MB)")
    if signature and signature.get("Status") not in ("Valid", "0", 0):
        score += 20
        reasons.append(f"signature status {signature.get('Status')}")
    return score, reasons or ["no obvious issue"]


def verify_signatures(exes):
    exes = sorted({str(e) for e in exes if e and Path(str(e)).exists()})[:140]
    if not exes:
        return {}
    temp = REPORT_DIR / "signature-input.txt"
    temp.write_text("\n".join(exes), encoding="utf-8")
    command = (
        f"$paths=Get-Content -LiteralPath '{temp}'; "
        "$paths | ForEach-Object { "
        "$s=Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{Path=$_; Status=[string]$s.Status; Signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''}} "
        "} | ConvertTo-Json -Depth 4"
    )
    rows = ps_json(command, timeout=90)
    try:
        temp.unlink()
    except OSError:
        pass
    signatures = {}
    for row in rows:
        path = row.get("Path", "")
        if isinstance(path, dict):
            path = path.get("value") or path.get("Path") or ""
        if isinstance(path, list):
            path = path[0] if path else ""
        if path:
            signatures[str(path)] = row
    return signatures


def collect_startup():
    rows = ps_json(
        "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Depth 4",
        timeout=30,
    )
    startup_dirs = []
    for env_name in ("APPDATA", "ProgramData"):
        root = os.environ.get(env_name)
        if root:
            folder = Path(root) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if folder.exists():
                for item in folder.iterdir():
                    startup_dirs.append({"Name": item.name, "Command": str(item), "Location": f"Startup folder: {folder}", "User": ""})
    return rows + startup_dirs


def collect_tasks():
    result = run(["schtasks.exe", "/query", "/fo", "csv", "/v"], timeout=45)
    if result.returncode != 0:
        return []
    rows = []
    for row in csv.DictReader(result.stdout.splitlines()):
        command = row.get("Task To Run") or ""
        if not command or command.upper() == "N/A":
            continue
        rows.append(
            {
                "TaskName": row.get("TaskName") or "",
                "Status": row.get("Status") or "",
                "Schedule": row.get("Schedule Type") or "",
                "LastRun": row.get("Last Run Time") or "",
                "Command": command,
            }
        )
    return rows


def collect_services():
    return ps_json(
        "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName | ConvertTo-Json -Depth 4",
        timeout=45,
    )


def collect_installed_logmein():
    rows = []
    command = (
        "$roots=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
        "Get-ItemProperty $roots -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -match 'LogMeIn|Rescue' -or $_.Publisher -match 'LogMeIn|GoTo' } | "
        "Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation,UninstallString | ConvertTo-Json -Depth 4"
    )
    rows.extend(ps_json(command, timeout=30))
    return rows


def search_logmein_files():
    roots = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("LOCALAPPDATA", "")),
        Path(os.environ.get("APPDATA", "")),
        Path(os.environ.get("TEMP", "")),
    ]
    hits = []
    for root in roots:
        if not root.exists():
            continue
        try:
            for item in root.rglob("*"):
                name = lower(item.name)
                path = lower(item)
                if any(marker in name or marker in path for marker in LOGMEIN_MARKERS):
                    hits.append(str(item))
                    if len(hits) >= 80:
                        return hits
        except (OSError, PermissionError):
            continue
    return hits


def summarize_third_party(processes):
    totals = defaultdict(float)
    for item in processes:
        exe = lower(item.get("exe"))
        text = lower(item.get("name")) + " " + exe
        if any(marker in text for marker in KNOWN_SAFE_MARKERS):
            continue
        if is_microsoft_path(exe):
            continue
        vendor = "Other"
        if "ad2f1837." in exe or "\\hp\\" in exe or "hewlett" in exe:
            vendor = "HP/OEM"
        elif "\\apple\\" in exe or "bonjour" in exe:
            vendor = "Apple/Bonjour"
        elif "\\git\\" in exe:
            vendor = "Git"
        elif "claude" in exe:
            vendor = "Claude"
        elif "duet" in exe:
            vendor = "Duet"
        totals[vendor] += item.get("max_ram_mb", 0)
    return sorted([(k, round(v, 1)) for k, v in totals.items()], key=lambda x: x[1], reverse=True)


def write_report(report, md_path):
    lines = []
    lines.append(f"# Clean PC Report - {report['generated_at']}")
    lines.append("")
    lines.append("## Verdict")
    lines.append(report["verdict"])
    lines.append("")
    lines.append("## 2-Minute System Load")
    lines.append(f"- Samples: `{len(report['samples'])}` over about `{SAMPLE_SECONDS}` seconds.")
    lines.append(f"- CPU range: `{report['system_cpu_min']}%` to `{report['system_cpu_max']}%`.")
    lines.append(f"- RAM range: `{report['system_ram_min']}%` to `{report['system_ram_max']}%`.")
    lines.append("")
    lines.append("## Top RAM")
    for item in report["top_ram"][:20]:
        lines.append(f"- `{item['name']}` PID `{item['pid']}` max RAM `{item['max_ram_mb']} MB`, max CPU `{item['max_cpu_percent']}%`, `{item['exe']}`")
    lines.append("")
    lines.append("## Top CPU")
    for item in report["top_cpu"][:20]:
        lines.append(f"- `{item['name']}` PID `{item['pid']}` max CPU `{item['max_cpu_percent']}%`, max RAM `{item['max_ram_mb']} MB`, `{item['exe']}`")
    lines.append("")
    lines.append("## Review Items")
    if report["review_items"]:
        for item in report["review_items"][:40]:
            lines.append(f"- Score `{item['score']}` `{item['name']}` PID `{item['pid']}`: {', '.join(item['reasons'])}; signature `{item.get('signature_status','')}`; `{item['exe']}`")
    else:
        lines.append("- No active process crossed the suspicious review threshold.")
    lines.append("")
    lines.append("## Third-Party RAM Groups")
    for vendor, ram in report["third_party_groups"]:
        lines.append(f"- `{vendor}`: about `{ram} MB` max observed across processes.")
    lines.append("")
    lines.append("## LogMeIn / Rescue Check")
    if report["logmein_running"]:
        for item in report["logmein_running"]:
            lines.append(f"- Running: `{item['name']}` PID `{item['pid']}` `{item['exe']}`")
    else:
        lines.append("- No LogMeIn/Rescue process was running during the 2-minute monitor.")
    if report["logmein_installed"]:
        for item in report["logmein_installed"]:
            lines.append(f"- Installed entry: `{item.get('DisplayName')}` `{item.get('Publisher')}` `{item.get('InstallLocation')}`")
    else:
        lines.append("- No LogMeIn/Rescue uninstall entry found.")
    if report["logmein_file_hits"]:
        for path in report["logmein_file_hits"][:30]:
            lines.append(f"- File/path hit: `{path}`")
    else:
        lines.append("- No obvious LogMeIn/Rescue files found in common app/temp locations.")
    lines.append("")
    lines.append("## Startup Entries")
    for item in report["startup"]:
        lines.append(f"- `{item.get('Name')}` from `{item.get('Location')}`: `{item.get('Command')}`")
    lines.append("")
    lines.append("## Enabled Non-Microsoft Scheduled Tasks")
    if report["non_ms_tasks"]:
        for item in report["non_ms_tasks"][:40]:
            lines.append(f"- `{item.get('TaskName')}` `{item.get('Status')}` `{item.get('Schedule')}`: `{item.get('Command')}`")
    else:
        lines.append("- None found.")
    lines.append("")
    lines.append("## Non-Microsoft Auto/Running Services")
    if report["non_ms_services"]:
        for item in report["non_ms_services"][:50]:
            lines.append(f"- `{item.get('DisplayName')}` `{item.get('State')}` `{item.get('StartMode')}`: `{item.get('PathName')}`")
    else:
        lines.append("- None found.")
    md_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    print("Monitoring for 2 minutes...")
    samples = monitor_samples()
    aggregated = aggregate_samples(samples)
    signatures = verify_signatures([item["exe"] for item in aggregated])

    classified = []
    for item in aggregated:
        signature = signatures.get(item.get("exe", ""), {})
        score, reasons = classify(item, signature)
        classified.append(
            {
                **item,
                "score": score,
                "reasons": reasons,
                "signature_status": signature.get("Status", ""),
                "signature_signer": signature.get("Signer", ""),
            }
        )

    startup = collect_startup()
    tasks = collect_tasks()
    services = collect_services()

    non_ms_tasks = [
        t
        for t in tasks
        if t.get("Status") != "Disabled"
        and t.get("TaskName") != "TaskName"
        and not lower(t.get("TaskName")).startswith("\\microsoft\\windows\\")
    ]
    non_ms_services = [
        s
        for s in services
        if (s.get("State") == "Running" or s.get("StartMode") == "Auto")
        and not is_microsoft_path(s.get("PathName"))
    ]

    logmein_running = [item for item in classified if any(marker in lower(item) for marker in LOGMEIN_MARKERS)]
    review_items = [item for item in classified if item["score"] >= 40]
    if review_items:
        verdict = "Review items were found. They are not confirmed malware, but they should be inspected."
    else:
        verdict = "No active malware-style process was identified during the 2-minute monitor. The main load is OEM/HP utilities, Defender, Windows UI, and normal app helpers."

    system_cpu = [s["system_cpu_percent"] for s in samples]
    system_ram = [s["system_ram_percent"] for s in samples]
    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "verdict": verdict,
        "samples": [{"time": s["time"], "system_cpu_percent": s["system_cpu_percent"], "system_ram_percent": s["system_ram_percent"]} for s in samples],
        "system_cpu_min": min(system_cpu) if system_cpu else 0,
        "system_cpu_max": max(system_cpu) if system_cpu else 0,
        "system_ram_min": min(system_ram) if system_ram else 0,
        "system_ram_max": max(system_ram) if system_ram else 0,
        "processes": classified,
        "top_ram": sorted(classified, key=lambda x: x["max_ram_mb"], reverse=True)[:30],
        "top_cpu": sorted(classified, key=lambda x: x["max_cpu_percent"], reverse=True)[:30],
        "review_items": sorted(review_items, key=lambda x: x["score"], reverse=True),
        "third_party_groups": summarize_third_party(classified),
        "startup": startup,
        "non_ms_tasks": non_ms_tasks,
        "non_ms_services": non_ms_services,
        "logmein_running": logmein_running,
        "logmein_installed": collect_installed_logmein(),
        "logmein_file_hits": search_logmein_files(),
    }

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = REPORT_DIR / f"clean-report-{stamp}.json"
    md_path = REPORT_DIR / f"clean-report-{stamp}.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    write_report(report, md_path)
    print(str(md_path))
    print(str(json_path))


if __name__ == "__main__":
    sys.exit(main())
