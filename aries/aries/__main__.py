"""ARIES entry point — Interactive System Auditing Terminal for Arch Linux."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich.align import Align
from rich import box

from aries import __version__
from aries.banner import render_banner, render_compact_banner
from aries.menu import arrow_menu, _flush_stdin
from audits import (
    SystemInfo,
    Resources,
    Security,
    Packages,
    Services,
    Users,
    Filesystem,
)
from audits.base import Severity, SectionResult

console = Console()

SEVERITY_STYLE = {
    Severity.OK: "bold green",
    Severity.INFO: "bold cyan",
    Severity.WARN: "bold yellow",
    Severity.CRITICAL: "bold red",
    Severity.SKIP: "dim",
}

SEVERITY_ICON = {
    Severity.OK: "✓",
    Severity.INFO: "•",
    Severity.WARN: "!",
    Severity.CRITICAL: "✗",
    Severity.SKIP: "–",
}

MODULES = {
    "1": ("System", SystemInfo),
    "2": ("Resources", Resources),
    "3": ("Security", Security),
    "4": ("Packages", Packages),
    "5": ("Services", Services),
    "6": ("Users", Users),
    "7": ("Filesystem", Filesystem),
}

MAIN_OPTIONS = [
    ("Full Audit", "all modules including file scan", "full"),
    ("Quick Scan", "system + resources + services", "quick"),
    ("Security Focus", "security + users + packages + filesystem", "security"),
    ("Deep File Scan", "walk /etc /tmp /home /opt …", "files"),
    ("Pick Sections", "toggle individual modules", "pick"),
    ("Export last results (JSON)", "if available", "export"),
    ("Show Banner again", "", "banner"),
    ("Quit", "", "quit"),
]


def render_section(result: SectionResult) -> None:
    table = Table(
        show_header=True,
        header_style="bold #C0C0C0",
        box=box.SIMPLE_HEAD,
        border_style="#505050",
        expand=True,
        pad_edge=False,
    )
    table.add_column("Status", width=10, justify="center")
    table.add_column("Check", style="#E0E0E0", ratio=2)
    table.add_column("Detail", style="#A0A0A0", ratio=4)
    table.add_column("Recommendation", style="dim #808080", ratio=3)

    for f in result.findings:
        icon = SEVERITY_ICON.get(f.status, "?")
        style = SEVERITY_STYLE.get(f.status, "")
        status_cell = Text(f"{icon} {f.status.value.upper()}", style=style)
        table.add_row(status_cell, f.title, f.detail or "—", f.recommendation or "")

    panel = Panel(
        table,
        title=f"[bold #C0C0C0]{result.name}[/]",
        title_align="left",
        border_style="#606060",
        padding=(0, 1),
    )
    console.print(panel)
    console.print()


def run_audits(module_keys: list[str]) -> list[SectionResult]:
    selected = [MODULES[k] for k in module_keys if k in MODULES]
    results: list[SectionResult] = []
    total = len(selected)
    for i, (name, cls) in enumerate(selected, 1):
        with console.status(
            f"[bold #A0A0A0][{i}/{total}] Scanning {name}…[/]",
            spinner="dots",
        ):
            result = cls().run()
        results.append(result)
        render_section(result)
    return results


def summary(results: list[SectionResult]) -> None:
    counts = {s: 0 for s in Severity}
    for r in results:
        for f in r.findings:
            counts[f.status] += 1

    parts = []
    if counts[Severity.CRITICAL]:
        parts.append(f"[bold red]{counts[Severity.CRITICAL]} critical[/]")
    if counts[Severity.WARN]:
        parts.append(f"[bold yellow]{counts[Severity.WARN]} warnings[/]")
    if counts[Severity.OK]:
        parts.append(f"[bold green]{counts[Severity.OK]} ok[/]")
    if counts[Severity.INFO]:
        parts.append(f"[cyan]{counts[Severity.INFO]} info[/]")

    text = "  •  ".join(parts) if parts else "No findings"
    console.print(
        Panel(
            Text.from_markup(text, justify="center"),
            title="[bold #C0C0C0]Summary[/]",
            border_style="#606060",
        )
    )
    console.print()


def to_json(results: list[SectionResult]) -> str:
    data = {
        "tool": "ARIES",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sections": [
            {
                "name": r.name,
                "findings": [
                    {
                        "title": f.title,
                        "status": f.status.value,
                        "detail": f.detail,
                        "recommendation": f.recommendation,
                    }
                    for f in r.findings
                ],
                "raw": r.raw,
            }
            for r in results
        ],
    }
    return json.dumps(data, indent=2)


def pick_sections_menu() -> list[str]:
    keys = list(MODULES.keys())
    labels = [MODULES[k][0] for k in keys]
    active = [False] * len(labels)

    while True:
        display = []
        for i, name in enumerate(labels):
            mark = "●" if active[i] else "○"
            display.append(
                (f"{mark}  {name}", "ON" if active[i] else "off")
            )
        display.append(("✓  Done — run selected", "finish"))

        idx = arrow_menu(console, "Pick Sections  (Enter toggles)", display)
        if idx is None:
            return []
        if idx == len(labels):
            return [keys[i] for i, on in enumerate(active) if on]
        active[idx] = not active[idx]
        # no full clear — just continue; menu redraws on next call


def interactive_loop() -> None:
    last_results: list[SectionResult] = []

    while True:
        opts = [(label, desc) for label, desc, _ in MAIN_OPTIONS]
        idx = arrow_menu(console, "Main Menu", opts)

        if idx is None:
            action = "quit"
        else:
            action = MAIN_OPTIONS[idx][2]

        if action == "quit":
            console.print(
                Align.center(Text("ARIES out. Stay secure.", style="dim #808080"))
            )
            console.print()
            break

        if action == "banner":
            console.clear()
            render_banner(console, version=__version__)
            continue

        if action == "export":
            if not last_results:
                console.print("[yellow]No results yet. Run an audit first.[/]\n")
                continue
            path = Prompt.ask("Save JSON to", default="aries-report.json")
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(to_json(last_results))
                console.print(f"[green]Saved → {path}[/]\n")
            except Exception as exc:
                console.print(f"[red]Failed to write: {exc}[/]\n")
            continue

        if action == "full":
            keys = list(MODULES.keys())
        elif action == "quick":
            keys = ["1", "2", "5"]
        elif action == "security":
            keys = ["3", "6", "4", "7"]
        elif action == "files":
            keys = ["7"]
        elif action == "pick":
            keys = pick_sections_menu()
            if not keys:
                console.print("[yellow]Nothing selected.[/]\n")
                continue
        else:
            continue

        console.rule("[bold #A0A0A0]Running audit[/]", style="#505050")
        console.print()
        last_results = run_audits(keys)
        summary(last_results)

        console.print(
            Text(
                "Press Enter to return to menu…",
                style="dim #606060",
                justify="center",
            )
        )
        _flush_stdin()
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            break
        _flush_stdin()
        console.print()
        render_compact_banner(console)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--quick", "-q", is_flag=True, help="Non-interactive quick overview")
@click.option("--json", "as_json", is_flag=True, help="Non-interactive JSON output")
@click.option(
    "--section",
    "-s",
    multiple=True,
    type=click.Choice(
        ["system", "resources", "security", "packages", "services", "users", "filesystem"],
        case_sensitive=False,
    ),
    help="Non-interactive: run only selected section(s)",
)
@click.option("--no-banner", is_flag=True, help="Skip banner (scripts)")
@click.version_option(__version__, prog_name="ARIES")
def main(quick: bool, as_json: bool, section: tuple[str, ...], no_banner: bool) -> None:
    """
    ARIES — interactive system auditing terminal for Arch Linux.

    Run without flags for the interactive menu (j/k to navigate).
    """
    if as_json or quick or section:
        name_to_key = {v[0].lower(): k for k, v in MODULES.items()}
        if section:
            keys = [name_to_key[s.lower()] for s in section if s.lower() in name_to_key]
        elif quick:
            keys = ["1", "2", "5"]
        else:
            keys = list(MODULES.keys())

        results = [MODULES[k][1]().run() for k in keys]

        if as_json:
            print(to_json(results))
            return

        if not no_banner:
            render_banner(console, version=__version__)
        for r in results:
            render_section(r)
        summary(results)
        return

    if not no_banner:
        render_banner(console, version=__version__)

    try:
        interactive_loop()
    except KeyboardInterrupt:
        console.print("\n")
        console.print(
            Align.center(Text("Interrupted. ARIES out.", style="dim #808080"))
        )
        console.print()


if __name__ == "__main__":
    main()
