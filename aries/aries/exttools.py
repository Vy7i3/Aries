"""
Wrappers for verified open-source security tools when installed on the system.

Projects referenced (public GitHub / long-standing FOSS):
- CISOfy/lynis          — system audit & hardening (GPL-3.0)
- Cisco-Talos/clamav   — antivirus engine (GPL-2.0)
- chkrootkit/chkrootkit — local rootkit checks
- Rootkit-Hunter/rkhunter — rootkit hunter
- OSSEC / classic FIM patterns for integrity ideas (implemented in scanner.py)

We do not vendor their full codebases; we invoke the installed binaries and
parse results, which is the safe/legal integration path for large tools.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.text import Text


@dataclass
class ToolResult:
    name: str
    available: bool
    output: str
    returncode: int | None = None


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def run_tool(cmd: list[str], timeout: int = 300) -> ToolResult:
    name = cmd[0]
    path = which(cmd[0])
    if not path:
        return ToolResult(name=name, available=False, output=f"{name} not installed", returncode=None)
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
        return ToolResult(name=name, available=True, output=out.strip(), returncode=r.returncode)
    except subprocess.TimeoutExpired:
        return ToolResult(name=name, available=True, output=f"{name} timed out after {timeout}s", returncode=-1)
    except OSError as exc:
        return ToolResult(name=name, available=True, output=str(exc), returncode=-1)


def run_lynis(console: Console) -> ToolResult:
    """CISOfy Lynis — prefer non-interactive audit."""
    if not which("lynis"):
        console.print(
            "[yellow]lynis not found.[/] Install now: [bold]sudo pacman -S lynis[/] "
            "or from https://github.com/CISOfy/lynis"
        )
        return ToolResult("lynis", False, "not installed")
    console.print("[bold #A0A0A0]Running lynis audit system (this can take a few minutes)…[/]")
    # --quiet reduces noise; still produces report under /var/log if root
    return run_tool(["lynis", "audit", "system", "--quick"], timeout=600)


def run_chkrootkit(console: Console) -> ToolResult:
    if not which("chkrootkit"):
        console.print(
            "[yellow]chkrootkit not found.[/] Install now: [bold]sudo pacman -S chkrootkit[/] "
            "or https://github.com/chkrootkit/chkrootkit"
        )
        return ToolResult("chkrootkit", False, "not installed")
    console.print("[bold #A0A0A0]Running chkrootkit…[/]")
    return run_tool(["chkrootkit"], timeout=300)


def run_rkhunter(console: Console) -> ToolResult:
    if not which("rkhunter"):
        console.print(
            "[yellow]rkhunter not found.[/] Install: [bold]sudo pacman -S rkhunter[/] "
            "or https://github.com/Rootkit-Hunter/rkhunter"
        )
        return ToolResult("rkhunter", False, "not installed")
    console.print("[bold #A0A0A0]Running rkhunter --check --skip-keypress…[/]")
    return run_tool(
        ["rkhunter", "--check", "--skip-keypress", "--report-warnings-only"],
        timeout=600,
    )


def run_clamscan_dir(console: Console, path: str = "/home") -> ToolResult:
    for binary in ("clamdscan", "clamscan"):
        if which(binary):
            console.print(f"[bold #A0A0A0]Running {binary} on {path}…[/]")
            if binary == "clamscan":
                return run_tool([binary, "-r", "--bell", "-i", path], timeout=900)
            return run_tool([binary, "-r", path], timeout=900)
    console.print(
        "[yellow]ClamAV not found.[/] Install: [bold]sudo pacman -S clamav && sudo freshclam[/] "
        "— https://github.com/Cisco-Talos/clamav"
    )
    return ToolResult("clamav", False, "not installed")


def show_tool_result(console: Console, result: ToolResult, max_lines: int = 80) -> None:
    if not result.available:
        console.print(f"[dim]{result.output}[/]\n")
        return
    lines = result.output.splitlines()
    truncated = lines[:max_lines]
    body = "\n".join(truncated)
    if len(lines) > max_lines:
        body += f"\n… ({len(lines) - max_lines} more lines)"
    console.print(
        Panel(
            Text(body or "(no output)", style="#C0C0C0"),
            title=f"[bold #C0C0C0]{result.name}[/]  exit={result.returncode}",
            border_style="#606060",
        )
    )
    console.print()
