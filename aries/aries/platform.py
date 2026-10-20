"""Host OS detection for ARIES (linux / windows / macos)."""

from __future__ import annotations

import os
import sys
from functools import lru_cache


@lru_cache(maxsize=1)
def detect_os() -> str:
    """
    Return one of: 'linux', 'windows', 'macos', 'unknown'.
    """
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform in ("win32", "cygwin", "msys") or os.name == "nt":
        return "windows"
    return "unknown"


def os_label() -> str:
    return {
        "linux": "Linux",
        "windows": "Windows",
        "macos": "macOS",
        "unknown": "Unknown OS",
    }.get(detect_os(), "Unknown OS")


def is_linux() -> bool:
    return detect_os() == "linux"


def is_windows() -> bool:
    return detect_os() == "windows"


def is_macos() -> bool:
    return detect_os() == "macos"


def path_sep() -> str:
    return "\\" if is_windows() else "/"


def default_scan_roots() -> list[str]:
    """OS-appropriate roots for deep file / malware scans."""
    kind = detect_os()
    if kind == "windows":
        roots = [
            os.environ.get("USERPROFILE") or "C:\\Users",
            os.environ.get("PROGRAMDATA") or "C:\\ProgramData",
            os.environ.get("TEMP") or "C:\\Windows\\Temp",
            "C:\\Windows\\Temp",
            "C:\\Temp",
            "C:\\Windows\\System32\\drivers\\etc",
            "C:\\Windows\\System32\\Tasks",
        ]
        return [r for r in roots if r and os.path.isdir(r)]
    if kind == "macos":
        roots = [
            "/Users",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/tmp",
            "/var/tmp",
            "/usr/local/bin",
            "/Applications",
            "/private/etc",
            "/Library/StartupItems",
        ]
        home = os.path.expanduser("~")
        if home and home not in roots:
            roots.insert(0, home)
        return [r for r in roots if os.path.isdir(r)]
    # linux default
    roots = [
        "/etc",
        "/tmp",
        "/var/tmp",
        "/var/spool/cron",
        "/etc/cron.d",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/opt",
        "/home",
        "/root",
        "/boot",
        "/usr/bin",
        "/usr/sbin",
    ]
    return [r for r in roots if os.path.isdir(r) or os.path.isfile(r)]


def skip_dir_names() -> set[str]:
    base = {
        "proc", "sys", "dev", "run", "snap", "node_modules",
        ".cache", ".npm", ".cargo", "__pycache__", ".git",
        "lost+found", "containers", "docker", "signatures",
        ".venv", "venv",
    }
    if detect_os() == "windows":
        base |= {
            "WinSxS", "ServiceProfiles", "System Volume Information",
            "$Recycle.Bin", "Windows.old", "Packages",
        }
    if detect_os() == "macos":
        base |= {
            "Caches", "Time Machine Backups", ".Spotlight-V100",
            ".fseventsd", "Containers",
        }
    return base
