import csv
import ctypes
import json
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from pc_usage_watchdog.paths import data_root

try:
    import psutil
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Missing dependency",
        "psutil is not installed. Run install.bat, then start the app again.",
    )
    raise


APP_NAME = "PC Usage Watchdog"
BASE_DIR = data_root()
LOG_DIR = BASE_DIR / "logs"
EVENT_LOG = LOG_DIR / "process_events.jsonl"
REFRESH_MS = 1500
POLL_FALLBACK_INTERVAL = 0.10

CRITICAL_NAMES = {
    "system idle process",
    "system",
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

SCRIPT_OR_LOL_BIN_NAMES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "conhost.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "bitsadmin.exe",
    "certutil.exe",
    "schtasks.exe",
    "python.exe",
    "pythonw.exe",
    "node.exe",
}

USUAL_BACKGROUND_NOISE = {
    "onedrive.exe",
    "teams.exe",
    "msedge.exe",
    "chrome.exe",
    "discord.exe",
    "steam.exe",
    "epicgameslauncher.exe",
    "spotify.exe",
    "adobecollabsync.exe",
    "creative cloud.exe",
    "update.exe",
}


def is_codex_helper(name: str, exe: str, cmdline: str) -> bool:
    text = f"{name} {exe} {cmdline}".lower()
    return "\\openai\\codex" in text or "program files\\windowsapps\\openai.codex" in text


def is_windows_internal(name: str) -> bool:
    return safe_lower(name) in CRITICAL_NAMES


@dataclass
class ProcessSnapshot:
    pid: int
    ppid: int
    name: str
    username: str
    cpu: float
    mem_mb: float
    create_time: float
    exe: str
    cmdline: str
    status: str
    reasons: list[str] = field(default_factory=list)
    score: int = 0

    @property
    def age_seconds(self) -> float:
        return max(0.0, time.time() - self.create_time)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def format_age(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h {minutes % 60}m"
    days = hours // 24
    return f"{days}d {hours % 24}h"


def safe_lower(value: str) -> str:
    return (value or "").lower()


def is_user_writable_path(path: str) -> bool:
    lower = safe_lower(path)
    markers = [
        "\\appdata\\",
        "\\temp\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\documents\\",
        "\\users\\public\\",
        "\\programdata\\",
    ]
    return any(marker in lower for marker in markers)


def is_system_path(path: str) -> bool:
    lower = safe_lower(path)
    if lower.startswith(r"c:\programdata\microsoft\windows defender\platform\\") or lower.startswith(
        r"c:\programdata\microsoft\windows defender\platform"
    ):
        return True
    windows = safe_lower(os.environ.get("WINDIR", r"C:\Windows"))
    program_files = safe_lower(os.environ.get("ProgramFiles", r"C:\Program Files"))
    program_files_x86 = safe_lower(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    return lower.startswith(windows) or lower.startswith(program_files) or lower.startswith(program_files_x86)


def classify_process(proc: ProcessSnapshot) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    name = safe_lower(proc.name)
    exe = safe_lower(proc.exe)
    cmd = safe_lower(proc.cmdline)

    if is_codex_helper(proc.name, proc.exe, proc.cmdline):
        return 0, ["OpenAI Codex helper"]

    if name in CRITICAL_NAMES:
        return 0, ["Windows core process"]

    if proc.cpu >= 35:
        score += 35
        reasons.append(f"High CPU now ({proc.cpu:.0f}%)")
    elif proc.cpu >= 15:
        score += 15
        reasons.append(f"Moderate CPU now ({proc.cpu:.0f}%)")

    if proc.mem_mb >= 1000:
        score += 25
        reasons.append(f"High RAM ({proc.mem_mb:.0f} MB)")
    elif proc.mem_mb >= 400:
        score += 12
        reasons.append(f"Notable RAM ({proc.mem_mb:.0f} MB)")

    if name in SCRIPT_OR_LOL_BIN_NAMES:
        score += 25
        reasons.append("Console/script/admin tool")

    if proc.exe and is_user_writable_path(proc.exe) and not is_system_path(proc.exe):
        score += 25
        reasons.append("Runs from user-writable location")

    if any(marker in cmd for marker in [" -enc", "frombase64string", "iex ", "downloadstring", "hidden", "bypass"]):
        score += 35
        reasons.append("Suspicious command-line pattern")

    if name in USUAL_BACKGROUND_NOISE and proc.age_seconds > 3600 and proc.mem_mb >= 150:
        score += 15
        reasons.append("Common forgotten background app")

    if proc.age_seconds > 6 * 3600 and proc.mem_mb >= 250:
        score += 10
        reasons.append("Long-running memory user")

    if not proc.exe and name not in CRITICAL_NAMES:
        score += 8
        reasons.append("Executable path unavailable")

    if not reasons:
        reasons.append("No obvious issue")
    return score, reasons


def process_to_event(event: dict) -> str:
    return json.dumps(event, ensure_ascii=True, sort_keys=True)


class ProcessStartWatcher:
    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self.stop_event = threading.Event()
        self.ps_proc: subprocess.Popen | None = None
        self.poll_seen: set[int] = set()
        self.poll_baselined = False

    def start(self) -> None:
        threading.Thread(target=self._run_wmi_watcher, daemon=True).start()
        threading.Thread(target=self._run_polling_fallback, daemon=True).start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.ps_proc and self.ps_proc.poll() is None:
            self.ps_proc.terminate()

    def _emit(self, event: dict) -> None:
        event.setdefault("time", now_iso())
        event.setdefault("source", "unknown")
        self.event_queue.put(event)

    def _run_wmi_watcher(self) -> None:
        if os.name != "nt":
            return
        script = r"""
$ErrorActionPreference = "Stop"
$query = "SELECT * FROM Win32_ProcessStartTrace"
$registered = $false
try {
  Register-WmiEvent -Query $query -SourceIdentifier ProcessStartWatcher | Out-Null
  $registered = $true
  while ($true) {
    $event = Wait-Event -SourceIdentifier ProcessStartWatcher -Timeout 1
    if ($null -ne $event) {
      $e = $event.SourceEventArgs.NewEvent
      $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$($e.ProcessID)" -ErrorAction SilentlyContinue
      $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($e.ParentProcessID)" -ErrorAction SilentlyContinue
      [pscustomobject]@{
        time = (Get-Date).ToString("o")
        source = "wmi"
        pid = [int]$e.ProcessID
        parent_pid = [int]$e.ParentProcessID
        name = [string]$e.ProcessName
        command_line = [string]$proc.CommandLine
        executable_path = [string]$proc.ExecutablePath
        parent_name = [string]$parent.Name
        parent_command_line = [string]$parent.CommandLine
      } | ConvertTo-Json -Compress
      Remove-Event -EventIdentifier $event.EventIdentifier
    }
  }
}
catch {
  [pscustomobject]@{
    time = (Get-Date).ToString("o")
    source = "watcher-error"
    pid = ""
    parent_pid = ""
    name = "PowerShell WMI watcher"
    command_line = "WMI process-start watcher failed: $($_.Exception.Message). Run this app as Administrator for best CMD-flash capture."
    executable_path = ""
    parent_name = ""
    parent_command_line = ""
  } | ConvertTo-Json -Compress
}
finally {
  if ($registered) {
    Unregister-Event -SourceIdentifier ProcessStartWatcher -ErrorAction SilentlyContinue
  }
}
"""
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            self.ps_proc = subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                creationflags=creationflags,
            )
            assert self.ps_proc.stdout is not None
            for line in self.ps_proc.stdout:
                if self.stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    self._emit(event)
                except json.JSONDecodeError:
                    continue
        except Exception as exc:
            self._emit(
                {
                    "source": "watcher-error",
                    "name": "PowerShell WMI watcher",
                    "command_line": str(exc),
                }
            )

    def _run_polling_fallback(self) -> None:
        while not self.stop_event.is_set():
            try:
                current_pids: set[int] = set()
                for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]):
                    info = proc.info
                    pid = int(info.get("pid") or 0)
                    current_pids.add(pid)
                    if pid in self.poll_seen:
                        continue
                    self.poll_seen.add(pid)
                    if not self.poll_baselined:
                        continue
                    created = float(info.get("create_time") or time.time())
                    if time.time() - created > 8:
                        continue
                    cmdline = " ".join(info.get("cmdline") or [])
                    self._emit(
                        {
                            "source": "poll",
                            "pid": pid,
                            "parent_pid": info.get("ppid"),
                            "name": info.get("name") or "",
                            "command_line": cmdline,
                            "executable_path": info.get("exe") or "",
                        }
                    )
                self.poll_seen.intersection_update(current_pids)
                self.poll_baselined = True
            except Exception:
                pass
            self.stop_event.wait(POLL_FALLBACK_INTERVAL)


class MonitorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1180x760")
        self.minsize(980, 620)

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.event_queue: queue.Queue = queue.Queue()
        self.events: deque[dict] = deque(maxlen=2000)
        self.process_rows: dict[str, ProcessSnapshot] = {}
        self.sort_key = "score"
        self.sort_reverse = True
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Starting watcher...")
        self.metric_var = tk.StringVar(value="CPU: --%   RAM: --%")
        self.only_flagged_var = tk.BooleanVar(value=False)
        self.show_windows_internal_var = tk.BooleanVar(value=False)
        self.admin_var = tk.StringVar(value=self._admin_status_text())
        self.event_keys: deque[tuple] = deque(maxlen=500)
        self.event_key_set: set[tuple] = set()

        self._configure_style()
        self._build_ui()

        self.watcher = ProcessStartWatcher(self.event_queue)
        self.watcher.start()

        psutil.cpu_percent(interval=None)
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(interval=None)
            except Exception:
                pass

        self.after(200, self._drain_events)
        self.after(500, self._refresh_processes)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        self.configure(bg="#111827")
        style.configure("TFrame", background="#111827")
        style.configure("Panel.TFrame", background="#172033")
        style.configure("TLabel", background="#111827", foreground="#e5e7eb", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#111827", foreground="#f9fafb", font=("Segoe UI Semibold", 20))
        style.configure("Metric.TLabel", background="#172033", foreground="#fef3c7", font=("Consolas", 16, "bold"))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("TCheckbutton", background="#111827", foreground="#e5e7eb")
        style.configure("Treeview", background="#0f172a", fieldbackground="#0f172a", foreground="#e5e7eb", rowheight=26)
        style.configure("Treeview.Heading", background="#1f2937", foreground="#f9fafb", font=("Segoe UI Semibold", 9))
        style.map("Treeview", background=[("selected", "#2563eb")])

    def _build_ui(self) -> None:
        header = ttk.Frame(self, padding=(16, 14, 16, 8))
        header.pack(fill=tk.X)

        ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(header, textvariable=self.metric_var, style="Metric.TLabel", padding=(16, 8)).pack(side=tk.RIGHT)

        controls = ttk.Frame(self, padding=(16, 0, 16, 8))
        controls.pack(fill=tk.X)
        ttk.Label(controls, text="Search").pack(side=tk.LEFT)
        search = ttk.Entry(controls, textvariable=self.search_var, width=34)
        search.pack(side=tk.LEFT, padx=(8, 14))
        search.bind("<KeyRelease>", lambda _event: self._render_process_rows())
        ttk.Checkbutton(
            controls,
            text="Show only review items",
            variable=self.only_flagged_var,
            command=self._render_process_rows,
        ).pack(side=tk.LEFT)
        ttk.Checkbutton(
            controls,
            text="Show Windows internals",
            variable=self.show_windows_internal_var,
            command=self._render_process_rows,
        ).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Label(controls, textvariable=self.admin_var).pack(side=tk.LEFT, padx=(16, 0))
        ttk.Button(controls, text="Refresh startup entries", command=self._refresh_startup_entries).pack(side=tk.RIGHT)

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 10))

        self.process_tab = ttk.Frame(notebook)
        self.events_tab = ttk.Frame(notebook)
        self.startup_tab = ttk.Frame(notebook)
        self.actions_tab = ttk.Frame(notebook)

        notebook.add(self.process_tab, text="Processes")
        notebook.add(self.events_tab, text="CMD flashes and starts")
        notebook.add(self.startup_tab, text="Startup/background")
        notebook.add(self.actions_tab, text="Actions")

        self._build_process_tab()
        self._build_events_tab()
        self._build_startup_tab()
        self._build_actions_tab()

        footer = ttk.Frame(self, padding=(16, 0, 16, 12))
        footer.pack(fill=tk.X)
        ttk.Label(footer, textvariable=self.status_var).pack(side=tk.LEFT)
        ttk.Button(footer, text="Open logs folder", command=self._open_logs).pack(side=tk.RIGHT)

    def _build_process_tab(self) -> None:
        columns = ("score", "pid", "name", "cpu", "mem", "age", "user", "reasons", "path")
        self.process_tree = ttk.Treeview(self.process_tab, columns=columns, show="headings")
        headings = {
            "score": "Review",
            "pid": "PID",
            "name": "Process",
            "cpu": "CPU %",
            "mem": "RAM MB",
            "age": "Age",
            "user": "User",
            "reasons": "Reason",
            "path": "Path",
        }
        widths = {
            "score": 70,
            "pid": 70,
            "name": 190,
            "cpu": 80,
            "mem": 90,
            "age": 80,
            "user": 150,
            "reasons": 310,
            "path": 420,
        }
        for col in columns:
            self.process_tree.heading(col, text=headings[col], command=lambda c=col: self._sort_processes(c))
            self.process_tree.column(col, width=widths[col], anchor=tk.W)
        self.process_tree.pack(fill=tk.BOTH, expand=True)

        buttons = ttk.Frame(self.process_tab, padding=(0, 8))
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="End selected process", command=self._kill_selected_process).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Copy selected details", command=self._copy_selected_process).pack(side=tk.LEFT, padx=8)
        ttk.Button(buttons, text="Export process CSV", command=self._export_process_csv).pack(side=tk.LEFT)

    def _build_events_tab(self) -> None:
        columns = ("time", "source", "pid", "name", "parent", "command")
        self.events_tree = ttk.Treeview(self.events_tab, columns=columns, show="headings")
        headings = {
            "time": "Time",
            "source": "Source",
            "pid": "PID",
            "name": "Process",
            "parent": "Parent",
            "command": "Command line",
        }
        widths = {
            "time": 190,
            "source": 80,
            "pid": 70,
            "name": 170,
            "parent": 170,
            "command": 720,
        }
        for col in columns:
            self.events_tree.heading(col, text=headings[col])
            self.events_tree.column(col, width=widths[col], anchor=tk.W)
        self.events_tree.pack(fill=tk.BOTH, expand=True)

        buttons = ttk.Frame(self.events_tab, padding=(0, 8))
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Copy selected event", command=self._copy_selected_event).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Clear visible events", command=self._clear_events).pack(side=tk.LEFT, padx=8)

    def _build_startup_tab(self) -> None:
        columns = ("source", "name", "trigger", "reason", "command")
        self.startup_tree = ttk.Treeview(self.startup_tab, columns=columns, show="headings")
        for col, width in [("source", 220), ("name", 260), ("trigger", 180), ("reason", 240), ("command", 700)]:
            self.startup_tree.heading(col, text=col.title())
            self.startup_tree.column(col, width=width, anchor=tk.W)
        self.startup_tree.pack(fill=tk.BOTH, expand=True)
        self.after(300, self._refresh_startup_entries)

    def _build_actions_tab(self) -> None:
        text = tk.Text(
            self.actions_tab,
            bg="#0f172a",
            fg="#e5e7eb",
            insertbackground="#e5e7eb",
            wrap=tk.WORD,
            relief=tk.FLAT,
            padx=16,
            pady=16,
            font=("Segoe UI", 10),
        )
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(
            tk.END,
            (
                "Recommended workflow\n\n"
                "1. Leave the app running while you use the PC.\n\n"
                "2. Use Processes to review high CPU, high RAM, startup noise, and unknown tools.\n\n"
                "3. Use CMD flashes and starts when a black command window appears briefly.\n\n"
                "4. Use Startup/background to find apps and tasks that keep coming back after restart.\n\n"
                "5. Copy details before ending a process you do not recognize.\n\n"
                "6. Run as Administrator when exact command-line capture is required.\n"
            ),
        )
        text.configure(state=tk.DISABLED)

    def _snapshot_processes(self) -> list[ProcessSnapshot]:
        snapshots: list[ProcessSnapshot] = []
        for proc in psutil.process_iter(["pid", "ppid", "name", "username", "memory_info", "create_time", "exe", "cmdline", "status"]):
            try:
                info = proc.info
                cmdline = " ".join(info.get("cmdline") or [])
                memory = info.get("memory_info")
                snap = ProcessSnapshot(
                    pid=int(info.get("pid") or 0),
                    ppid=int(info.get("ppid") or 0),
                    name=info.get("name") or "",
                    username=info.get("username") or "",
                    cpu=float(proc.cpu_percent(interval=None)),
                    mem_mb=(memory.rss / (1024 * 1024)) if memory else 0.0,
                    create_time=float(info.get("create_time") or time.time()),
                    exe=info.get("exe") or "",
                    cmdline=cmdline,
                    status=info.get("status") or "",
                )
                snap.score, snap.reasons = classify_process(snap)
                snapshots.append(snap)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return snapshots

    def _refresh_processes(self) -> None:
        try:
            cpu = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            self.metric_var.set(f"CPU: {cpu:5.1f}%   RAM: {memory.percent:5.1f}% ({memory.used / (1024**3):.1f}/{memory.total / (1024**3):.1f} GB)")
            snapshots = self._snapshot_processes()
            self.process_rows = {str(p.pid): p for p in snapshots}
            self._render_process_rows()
            flagged = sum(1 for p in snapshots if p.score >= 20)
            self.status_var.set(
                f"Watching {len(snapshots)} processes. Review items: {flagged}. Events logged: {len(self.events)}. Log: {EVENT_LOG}"
            )
        except Exception as exc:
            self.status_var.set(f"Refresh failed: {exc}")
        self.after(REFRESH_MS, self._refresh_processes)

    def _render_process_rows(self) -> None:
        search = safe_lower(self.search_var.get())
        only_flagged = self.only_flagged_var.get()
        show_windows_internal = self.show_windows_internal_var.get()
        rows = list(self.process_rows.values())

        def key_func(p: ProcessSnapshot):
            if self.sort_key == "pid":
                return p.pid
            if self.sort_key == "cpu":
                return p.cpu
            if self.sort_key == "mem":
                return p.mem_mb
            if self.sort_key == "age":
                return p.age_seconds
            if self.sort_key == "name":
                return safe_lower(p.name)
            return p.score

        rows.sort(key=key_func, reverse=self.sort_reverse)
        self.process_tree.delete(*self.process_tree.get_children())
        for p in rows:
            if not show_windows_internal and is_windows_internal(p.name):
                continue
            haystack = f"{p.name} {p.pid} {p.exe} {p.cmdline} {' '.join(p.reasons)}".lower()
            if search and search not in haystack:
                continue
            if only_flagged and p.score < 20:
                continue
            review = "High" if p.score >= 50 else "Check" if p.score >= 20 else "Low"
            self.process_tree.insert(
                "",
                tk.END,
                iid=str(p.pid),
                values=(
                    review,
                    p.pid,
                    p.name,
                    f"{p.cpu:.1f}",
                    f"{p.mem_mb:.1f}",
                    format_age(p.age_seconds),
                    p.username,
                    "; ".join(p.reasons),
                    p.exe or p.cmdline,
                ),
            )

    def _sort_processes(self, col: str) -> None:
        mapping = {"score": "score", "cpu": "cpu", "mem": "mem", "age": "age", "pid": "pid", "name": "name"}
        key = mapping.get(col, "score")
        if self.sort_key == key:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_key = key
            self.sort_reverse = True
        self._render_process_rows()

    def _drain_events(self) -> None:
        inserted = 0
        while True:
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break
            self._record_event(event)
            inserted += 1
        if inserted:
            self._trim_event_tree()
        self.after(250, self._drain_events)

    def _record_event(self, event: dict) -> None:
        event.setdefault("time", now_iso())
        key = (
            str(event.get("pid") or ""),
            safe_lower(str(event.get("name") or "")),
            safe_lower(str(event.get("command_line") or event.get("executable_path") or "")),
        )
        if key in self.event_key_set and key[0]:
            return
        if self.event_keys.maxlen and len(self.event_keys) >= self.event_keys.maxlen:
            old_key = self.event_keys.popleft()
            self.event_key_set.discard(old_key)
        self.event_keys.append(key)
        self.event_key_set.add(key)
        self.events.appendleft(event)
        with EVENT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(process_to_event(event) + "\n")
        name = event.get("name") or ""
        parent = event.get("parent_name") or event.get("parent_pid") or ""
        command = event.get("command_line") or event.get("executable_path") or ""
        self.events_tree.insert(
            "",
            0,
            values=(
                event.get("time") or "",
                event.get("source") or "",
                event.get("pid") or "",
                name,
                parent,
                command,
            ),
        )

    def _trim_event_tree(self) -> None:
        children = self.events_tree.get_children()
        if len(children) > 750:
            for item in children[750:]:
                self.events_tree.delete(item)

    def _selected_process(self) -> ProcessSnapshot | None:
        selected = self.process_tree.selection()
        if not selected:
            messagebox.showinfo("No process selected", "Select a process first.")
            return None
        return self.process_rows.get(selected[0])

    def _kill_selected_process(self) -> None:
        proc = self._selected_process()
        if not proc:
            return
        if safe_lower(proc.name) in CRITICAL_NAMES:
            messagebox.showwarning("Blocked", "This looks like a Windows core process. The app will not end it.")
            return
        if not messagebox.askyesno("End process", f"End {proc.name} (PID {proc.pid})?\n\n{proc.exe or proc.cmdline}"):
            return
        try:
            psutil.Process(proc.pid).terminate()
            self.status_var.set(f"Terminate requested for {proc.name} (PID {proc.pid}).")
        except Exception as exc:
            messagebox.showerror("Could not end process", str(exc))

    def _copy_selected_process(self) -> None:
        proc = self._selected_process()
        if not proc:
            return
        payload = {
            "pid": proc.pid,
            "ppid": proc.ppid,
            "name": proc.name,
            "username": proc.username,
            "cpu_percent": proc.cpu,
            "memory_mb": round(proc.mem_mb, 1),
            "age": format_age(proc.age_seconds),
            "exe": proc.exe,
            "cmdline": proc.cmdline,
            "reasons": proc.reasons,
        }
        self.clipboard_clear()
        self.clipboard_append(json.dumps(payload, indent=2, ensure_ascii=True))
        self.status_var.set("Selected process details copied.")

    def _copy_selected_event(self) -> None:
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showinfo("No event selected", "Select an event first.")
            return
        values = self.events_tree.item(selected[0], "values")
        payload = {
            "time": values[0],
            "source": values[1],
            "pid": values[2],
            "name": values[3],
            "parent": values[4],
            "command": values[5],
        }
        self.clipboard_clear()
        self.clipboard_append(json.dumps(payload, indent=2, ensure_ascii=True))
        self.status_var.set("Selected event copied.")

    def _clear_events(self) -> None:
        self.events.clear()
        self.events_tree.delete(*self.events_tree.get_children())
        self.status_var.set("Visible events cleared. Disk log was not deleted.")

    def _export_process_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export process list",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile=f"processes-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["pid", "ppid", "name", "cpu_percent", "memory_mb", "age", "user", "reasons", "exe", "cmdline"])
            for p in self.process_rows.values():
                writer.writerow([p.pid, p.ppid, p.name, p.cpu, f"{p.mem_mb:.1f}", format_age(p.age_seconds), p.username, "; ".join(p.reasons), p.exe, p.cmdline])
        self.status_var.set(f"Exported process list to {path}")

    def _refresh_startup_entries(self) -> None:
        self.startup_tree.delete(*self.startup_tree.get_children())
        self.startup_tree.insert("", tk.END, values=("Loading", "Startup and scheduled tasks", "", "", ""))
        threading.Thread(target=self._load_startup_entries_thread, daemon=True).start()

    def _load_startup_entries_thread(self) -> None:
        entries = self._get_startup_entries()
        self.after(0, lambda: self._render_startup_entries(entries))

    def _render_startup_entries(self, entries: list[tuple[str, str, str, str, str]]) -> None:
        self.startup_tree.delete(*self.startup_tree.get_children())
        for source, name, trigger, reason, command in entries:
            self.startup_tree.insert("", tk.END, values=(source, name, trigger, reason, command))
        self.status_var.set(f"Loaded {len(entries)} startup and scheduled-task entries.")

    def _get_startup_entries(self) -> list[tuple[str, str, str, str, str]]:
        entries: list[tuple[str, str, str, str, str]] = []
        if os.name == "nt":
            import winreg

            roots = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM WOW6432 Run"),
            ]
            for root, subkey, label in roots:
                try:
                    with winreg.OpenKey(root, subkey) as key:
                        index = 0
                        while True:
                            try:
                                name, value, _typ = winreg.EnumValue(key, index)
                                reason = self._startup_reason(str(value))
                                entries.append((label, name, "At sign-in", reason, str(value)))
                                index += 1
                            except OSError:
                                break
                except OSError:
                    continue

            startup_dirs = [
                Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
                Path(os.environ.get("ProgramData", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
            ]
            for folder in startup_dirs:
                if folder.exists():
                    for item in folder.iterdir():
                        reason = self._startup_reason(str(item))
                        entries.append((f"Startup folder: {folder}", item.name, "At sign-in", reason, str(item)))
            entries.extend(self._get_scheduled_task_entries())
        return entries

    def _get_scheduled_task_entries(self) -> list[tuple[str, str, str, str, str]]:
        entries: list[tuple[str, str, str, str, str]] = []
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            result = subprocess.run(
                ["schtasks.exe", "/query", "/fo", "csv", "/v"],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=creationflags,
            )
        except Exception as exc:
            return [("Scheduled tasks", "Could not query tasks", "", str(exc), "")]
        if result.returncode != 0:
            return [("Scheduled tasks", "Could not query tasks", "", result.stderr.strip(), "")]
        reader = csv.DictReader(result.stdout.splitlines())
        for row in reader:
            name = row.get("TaskName") or row.get("Task To Run") or ""
            command = row.get("Task To Run") or ""
            status = row.get("Status") or ""
            schedule = row.get("Schedule Type") or row.get("Next Run Time") or ""
            if not command or command.upper() == "N/A":
                continue
            reason = self._startup_reason(command)
            if reason == "Looks normal" and status.lower() == "disabled":
                continue
            entries.append(("Scheduled task", name, schedule or status, reason, command))
        return entries

    def _startup_reason(self, command: str) -> str:
        lower = safe_lower(command)
        reasons: list[str] = []
        if any(name in lower for name in SCRIPT_OR_LOL_BIN_NAMES):
            reasons.append("console/script tool")
        if is_user_writable_path(command) and not is_system_path(command):
            reasons.append("user-writable path")
        if any(marker in lower for marker in [" -enc", "frombase64string", "iex ", "downloadstring", "hidden", "bypass"]):
            reasons.append("suspicious pattern")
        return ", ".join(reasons) if reasons else "Looks normal"

    def _admin_status_text(self) -> str:
        if os.name != "nt":
            return ""
        try:
            return "Admin: yes" if ctypes.windll.shell32.IsUserAnAdmin() else "Admin: no, WMI capture may need admin"
        except Exception:
            return "Admin: unknown"

    def _open_logs(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(LOG_DIR)
        else:
            subprocess.Popen([sys.executable, "-m", "webbrowser", str(LOG_DIR)])

    def _on_close(self) -> None:
        self.watcher.stop()
        self.destroy()


def main() -> None:
    app = MonitorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
