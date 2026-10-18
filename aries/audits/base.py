"""Base helpers for audit modules."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    OK = "ok"
    WARN = "warn"
    CRITICAL = "critical"
    SKIP = "skip"


@dataclass
class Finding:
    title: str
    status: Severity
    detail: str = ""
    recommendation: str = ""


@dataclass
class SectionResult:
    name: str
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def add(
        self,
        title: str,
        status: Severity,
        detail: str = "",
        recommendation: str = "",
    ) -> None:
        self.findings.append(
            Finding(title=title, status=status, detail=detail, recommendation=recommendation)
        )


def run_cmd(
    cmd: list[str] | str,
    *,
    timeout: int = 15,
    check: bool = False,
    shell: bool = False,
) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        if isinstance(cmd, str) and not shell:
            cmd = cmd.split()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
            check=check,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:
        return 1, "", str(exc)


def file_exists(path: str) -> bool:
    import os
    return os.path.isfile(path)


def read_file(path: str, max_bytes: int = 64_000) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return None
