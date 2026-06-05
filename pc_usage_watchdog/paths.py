import os
import sys
from pathlib import Path


APP_DATA_DIR_NAME = "PCUsageWatchdog"


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def data_root() -> Path:
    """Return a writable root for logs and reports.

    Source checkouts keep artifacts beside the launchers for easy inspection.
    Installed packages and frozen builds use LocalAppData so they can run on any
    Windows PC without writing into Python's site-packages directory.
    """
    override = os.environ.get("PC_USAGE_WATCHDOG_HOME")
    if override:
        return Path(override).expanduser().resolve()

    root = project_root()
    if (root / "pyproject.toml").exists() and (root / "run.bat").exists():
        return root

    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / APP_DATA_DIR_NAME

    return Path.home() / f".{APP_DATA_DIR_NAME.lower()}"
