"""Dashboard: title left ABOVE box; goat in left box; features on the right."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.table import Table
from rich.text import Text
from rich import box

from aries.banner import make_title, make_goat
from aries import __version__

FEATURES = [
    ("full", "Full system audit", "All modules + deep file walk"),
    ("quick", "Quick scan", "System, resources, services"),
    ("security", "Security focus", "SSH, firewall, users, packages"),
    ("hardening", "Hardening checks", "kernel, sysctl, auth, mounts"),
    ("logs", "Log audit", "journal, failed logins, sudo, cron"),
    ("rootkit", "Rootkit checks", "indicators + external tools"),
    ("files", "Deep file scan", "Per-file hash + heuristics"),
    ("malware", "Malware scan", "ClamAV if installed"),
    ("rootkit", "Rootkit checks", "chkrootkit / rkhunter if installed"),
    ("lynis", "Lynis audit", "Run lynis if installed"),
    ("fim", "Integrity baseline", "Hash critical paths, detect changes"),
    ("system", "System info", "OS, kernel, uptime"),
    ("packages", "Packages", "Outdated / vulnerable (Arch)"),
    ("export", "Export JSON", "Save last results"),
    ("help", "Help", "Show commands"),
    ("quit", "Quit", "Exit ARIES"),
]


def render_dashboard(console: Console) -> None:
    # Title OUTSIDE the box, left side (above the goat box)
    console.print()
    console.print(make_title())
    console.print(Text(f"v{__version__}  •  Arch Linux", style="dim #808080"))
    console.print()

    goat_panel = Panel(
        make_goat(),
        title="[bold #C0C0C0]ARIES[/]",
        subtitle="[dim]black goat of the system[/]",
        border_style="#606060",
        box=box.ROUNDED,
        padding=(0, 1),
        title_align="left",
        subtitle_align="left",
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

    console.print(Columns([goat_panel, feat_panel], equal=False, expand=True))
    console.print()
    console.print(
        Text(
            "  type a command (full, files, malware, rootkit, lynis, …) or a path",
            style="dim #808080",
        )
    )
    console.print()
