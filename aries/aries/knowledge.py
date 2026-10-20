"""Load ARIES threat + hardening recommendation repository from repo/."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_REPO = _ROOT / "repo"


def repo_dir() -> Path:
    return _REPO


@lru_cache(maxsize=1)
def load_dangerous() -> dict[str, Any]:
    path = _REPO / "dangerous_indicators.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


@lru_cache(maxsize=1)
def load_systemd_hardening() -> dict[str, Any]:
    path = _REPO / "systemd_hardening.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def sysctl_recommendation(key: str) -> str | None:
    data = load_systemd_hardening().get("sysctl") or {}
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
    data = load_systemd_hardening().get("mount_options") or {}
    entry = data.get(mount)
    if not entry:
        return None
    return f"recommend options: {entry.get('optimal', '')} ({entry.get('why', '')})"


def sshd_recommendation(key: str) -> str | None:
    data = load_systemd_hardening().get("sshd") or {}
    entry = data.get(key)
    if not entry:
        return None
    return f"recommend {key} {entry.get('optimal', '')} — {entry.get('why', '')}"


def unit_hardening_tips() -> list[str]:
    data = load_systemd_hardening().get("systemd_unit_hardening") or {}
    tips = []
    for k, v in data.items():
        tips.append(f"{k}={v.get('optimal', '')} — {v.get('why', '')}")
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
