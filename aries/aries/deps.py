"""Detect optional tools and offer to install them (Arch Linux)."""

from __future__ import annotations

import shutil
import subprocess

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.text import Text


# (binary name, pacman package, short description)
OPTIONAL_TOOLS = [
    ("lynis", "lynis", "system auditing and hardening checks"),
    ("chkrootkit", "chkrootkit", "local rootkit indicator scanner"),
    ("rkhunter", "rkhunter", "rootkit hunter"),
    ("clamscan", "clamav", "antivirus scanner (also install clamav-db / run freshclam)"),
]


def missing_tools() -> list[tuple[str, str, str]]:
    return [(b, pkg, desc) for b, pkg, desc in OPTIONAL_TOOLS if not shutil.which(b)]


def prompt_install_missing(console: Console) -> None:
    """
    On startup: list missing tools and ask the user whether to install via pacman.
    Uses sudo pacman -S --needed. Never auto-installs without confirmation.
    """
    missing = missing_tools()
    if not missing:
        console.print(
            Panel(
                Text("Optional tools: lynis, chkrootkit, rkhunter, clamav — all found.", style="green"),
                border_style="#505050",
                title="[bold #C0C0C0]Dependencies[/]",
            )
        )
        console.print()
        return

    lines = ["These optional tools are not installed:\n"]
    for binary, pkg, desc in missing:
        lines.append(f"  • [bold]{pkg}[/] ([cyan]{binary}[/]) — {desc}")
    lines.append("")
    lines.append("ARIES works without them; they unlock extra commands (lynis, rootkit, malware).")

    console.print(
        Panel(
            Text.from_markup("\n".join(lines)),
            title="[bold #C0C0C0]Optional tools missing[/]",
            border_style="#606060",
        )
    )

    try:
        if not Confirm.ask("Install missing packages with pacman now?", default=False):
            console.print("[dim]Skipped. You can install later, e.g. sudo pacman -S lynis chkrootkit[/]\n")
            return
    except Exception:
        return

    packages = sorted({pkg for _, pkg, _ in missing})
    cmd = ["sudo", "pacman", "-S", "--needed", "--noconfirm", *packages]
    console.print(f"[bold #A0A0A0]Running:[/] {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd)
        if r.returncode == 0:
            console.print("[green]Install finished.[/]")
            still = missing_tools()
            if still:
                console.print(
                    "[yellow]Still missing:[/] "
                    + ", ".join(b for b, _, _ in still)
                    + " (may need a new shell or freshclam for clamav)"
                )
            else:
                console.print("[green]All optional tools are available.[/]")
        else:
            console.print(
                f"[red]pacman exited {r.returncode}.[/] "
                "Install manually: [bold]sudo pacman -S lynis chkrootkit rkhunter clamav[/]"
            )
    except FileNotFoundError:
        console.print("[red]sudo or pacman not found. Install packages manually.[/]")
    except Exception as exc:
        console.print(f"[red]Install failed:[/] {exc}")
    console.print()
