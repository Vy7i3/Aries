"""Load ARIES threat + hardening repos for the detected OS."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from aries.platform import detect_os

_ROOT = Path(__file__).resolve().parent.parent
_REPO = _ROOT / "repo"


def repo_dir() -> Path:
    return _REPO


def platform_repo_dir() -> Path:
    """repo/<linux|windows|macos>/ — falls back to linux if unknown."""
    kind = detect_os()
    if kind not in ("linux", "windows", "macos"):
        kind = "linux"
    path = _REPO / kind
    if path.is_dir():
        return path
    # legacy flat layout fallback
    return _REPO


@lru_cache(maxsize=4)
def load_dangerous(os_name: str | None = None) -> dict[str, Any]:
    kind = os_name or detect_os()
    if kind not in ("linux", "windows", "macos"):
        kind = "linux"
    candidates = [
        _REPO / kind / "dangerous_indicators.json",
        _REPO / "dangerous_indicators.json",  # legacy
    ]
    for path in candidates:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
    return {}


@lru_cache(maxsize=4)
def load_hardening(os_name: str | None = None) -> dict[str, Any]:
    kind = os_name or detect_os()
    if kind not in ("linux", "windows", "macos"):
        kind = "linux"
    candidates = [
        _REPO / kind / "hardening.json",
        _REPO / kind / "systemd_hardening.json",
        _REPO / "systemd_hardening.json",
        _REPO / "hardening.json",
    ]
    for path in candidates:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
    return {}


# Back-compat aliases used by older modules
def load_systemd_hardening() -> dict[str, Any]:
    return load_hardening()


def sysctl_recommendation(key: str) -> str | None:
    data = load_hardening().get("sysctl") or {}
    entry = data.get(key)
    if not entry:
        return None
    opt = entry.get("optimal", "")
    why = entry.get("why", "")
    how = entry.get("set", "")
    parts = [f"recommend {key}={opt}"]
    if why:
        parts.append(why)
    if how:
        parts.append(f"set: {how}")
    return " — ".join(parts)


def mount_recommendation(mount: str) -> str | None:
    data = load_hardening().get("mount_options") or {}
    entry = data.get(mount)
    if not entry:
        return None
    return f"recommend options: {entry.get('optimal', '')} ({entry.get('why', '')})"


def sshd_recommendation(key: str) -> str | None:
    data = load_hardening().get("sshd") or {}
    entry = data.get(key)
    if not entry:
        return None
    return f"recommend {key} {entry.get('optimal', '')} — {entry.get('why', '')}"


def unit_hardening_tips() -> list[str]:
    data = load_hardening().get("systemd_unit_hardening") or {}
    tips = []
    for k, v in data.items():
        tips.append(f"{k}={v.get('optimal', '')} — {v.get('why', '')}")
    return tips


def windows_hardening_tips() -> list[str]:
    data = load_hardening("windows")
    tips = []
    for section in ("registry_and_policy", "services", "firewall"):
        block = data.get(section) or {}
        for k, v in block.items():
            if isinstance(v, dict):
                tips.append(f"{k}={v.get('optimal', '')} — {v.get('why', '')}")
    return tips


def macos_hardening_tips() -> list[str]:
    data = load_hardening("macos")
    tips = []
    block = data.get("system") or {}
    for k, v in block.items():
        if isinstance(v, dict):
            tips.append(f"{k}: {v.get('optimal', '')} — {v.get('why', '')}")
    return tips


def dangerous_paths() -> list[str]:
    return list(load_dangerous().get("suspicious_paths") or [])


def dangerous_basenames() -> set[str]:
    return {x.lower() for x in (load_dangerous().get("suspicious_basenames") or [])}


def dangerous_process_names() -> list[str]:
    return list(load_dangerous().get("suspicious_process_names") or [])


def dangerous_modules() -> set[str]:
    return {x.lower() for x in (load_dangerous().get("suspicious_kernel_modules") or [])}


def critical_permission_files() -> dict[str, Any]:
    return dict(load_dangerous().get("critical_permission_files") or {})


def scan_roots_from_repo() -> list[str]:
    """Optional scan_roots override from dangerous_indicators.json."""
    roots = load_dangerous().get("scan_roots")
    if isinstance(roots, list) and roots:
        return [str(r) for r in roots]
    return []
