"""Dashboard: centered title + goat; tools + about on the right."""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.columns import Columns
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box

from aries.banner import make_title, make_goat, GOAT_PIXEL
from aries import __version__

FEATURES = [
    ("full", "Full system audit", "All modules + deep file walk"),
    ("quick", "Quick scan", "System, resources, services"),
    ("security", "Security focus", "SSH, firewall, users, packages"),
    ("hardening", "Hardening checks", "kernel, sysctl, auth, mounts"),
    ("logs", "Log audit", "journal, failed logins, sudo, cron"),
    ("files", "Deep file scan", "Per-file hash + heuristics"),
    ("malware", "Malware scan", "Local SHA-256 DB + ClamAV"),
    ("rootkit", "Rootkit checks", "indicators + external tools"),
    ("lynis", "Lynis audit", "Run lynis if installed"),
    ("fim", "Integrity baseline", "Hash critical paths, detect changes"),
    ("system", "System info", "OS, kernel, uptime"),
    ("packages", "Packages", "Outdated / vulnerable (Arch)"),
    ("export", "Export JSON", "Save last results"),
    ("help", "Help", "Show commands"),
    ("quit", "Quit", "Exit ARIES"),
]

ABOUT_TEXT = """\
ARIES is a local system auditing terminal for Arch Linux. \
It inspects hardening, services, users, packages, logs, and the filesystem, \
and can scan files against a built-in SHA-256 malware signature database. \
Optional tools (Lynis, chkrootkit, rkhunter, ClamAV) plug in when installed. \
Everything stays on your machine — no cloud account required.

Type a command from the list above, or a path like /etc/passwd to scan one file. \
Protected files will ask before using sudo."""


def render_dashboard(console: Console) -> None:
    console.print()
    # Centered title + version
    console.print(Align.center(make_title()))
    console.print(Align.center(Text(f"v{__version__}  •  Arch Linux", style="dim #808080")))
    console.print()

    goat_lines = len(GOAT_PIXEL.splitlines())

    goat_panel = Panel(
        Align.center(make_goat()),
        title="[bold #C0C0C0]ARIES[/]",
        subtitle="[dim]black goat of the system[/]",
        border_style="#606060",
        box=box.ROUNDED,
        padding=(0, 1),
        title_align="center",
        subtitle_align="center",
    )

    table = Table(
        show_header=True,
        header_style="bold #C0C0C0",
        box=box.SIMPLE_HEAD,
        border_style="#505050",
        expand=True,
        pad_edge=False,
    )
    table.add_column("Command", style="bold #E0E0E0", width=12)
    table.add_column("Feature", style="#C0C0C0")
    table.add_column("Description", style="dim #808080")
    for cmd, name, desc in FEATURES:
        table.add_row(cmd, name, desc)

    feat_panel = Panel(
        table,
        title="[bold #C0C0C0]Available tools[/]",
        subtitle="[dim]type a command or a file path[/]",
        border_style="#606060",
        box=box.ROUNDED,
        padding=(0, 1),
        title_align="left",
    )

    about_lines = Text()
    about_lines.append(ABOUT_TEXT, style="#A0A0A0")
    target_right = goat_lines + 4
    used = len(FEATURES) + 8
    pad = max(0, target_right - used - 6)
    if pad > 0:
        about_lines.append("\n" * pad)

    about_panel = Panel(
        about_lines,
        title="[bold #C0C0C0]About[/]",
        border_style="#606060",
        box=box.ROUNDED,
        padding=(1, 2),
        title_align="left",
    )

    right = Group(feat_panel, Text(""), about_panel)
    console.print(Columns([goat_panel, right], equal=False, expand=True))
    console.print()
    console.print(
        Align.center(
            Text(
                "type a command (full, files, malware, rootkit, lynis, …) or a path",
                style="dim #808080",
            )
        )
    )
    console.print()
