"""ARIES — Hermes-style dashboard + chat input + deep file scanning."""

from __future__ import annotations

import getpass
import json
import sys
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.align import Align
from rich import box

from aries import __version__
from aries.dashboard import render_dashboard, FEATURES
from aries.deps import prompt_install_missing
from aries.exttools import run_lynis, run_chkrootkit, run_rkhunter, show_tool_result
from aries.scanner import (
    deep_scan,
    build_baseline,
    compare_baseline,
    _clamscan_available,
    ScanReport,
)
from audits import (
    SystemInfo,
    Resources,
    Security,
    Packages,
    Services,
    Users,
    Filesystem,
    Hardening,
    RootkitIndicators,
    LogAudit,
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
    "system": SystemInfo,
    "resources": Resources,
    "security": Security,
    "packages": Packages,
    "services": Services,
    "users": Users,
    "filesystem": Filesystem,
    "hardening": Hardening,
    "rootkit_ind": RootkitIndicators,
    "logs": LogAudit,
}

# Alias map for chat commands
ALIASES = {
    "full": "full",
    "f": "full",
    "1": "full",
    "quick": "quick",
    "q": "quick",
    "2": "quick",
    "security": "security",
    "sec": "security",
    "3": "security",
    "files": "files",
    "file": "files",
    "scan": "files",
    "4": "files",
    "malware": "malware",
    "rootkit": "rootkit",
    "rk": "rootkit",
    "lynis": "lynis",
    "hardening": "hardening",
    "hard": "hardening",
    "logs": "logs",
    "log": "logs",
    "av": "malware",
    "virus": "malware",
    "5": "malware",
    "fim": "fim",
    "baseline": "fim",
    "integrity": "fim",
    "6": "fim",
    "system": "system",
    "packages": "packages",
    "export": "export",
    "help": "help",
    "h": "help",
    "?": "help",
    "quit": "quit",
    "exit": "quit",
    "q!": "quit",
}

last_results: list[SectionResult] = []
last_scan: ScanReport | None = None


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
        table.add_row(
            Text(f"{icon} {f.status.value.upper()}", style=style),
            f.title,
            f.detail or "—",
            f.recommendation or "",
        )

    console.print(
        Panel(
            table,
            title=f"[bold #C0C0C0]{result.name}[/]",
            border_style="#606060",
            padding=(0, 1),
        )
    )
    console.print()


def summary_sections(results: list[SectionResult]) -> None:
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
    console.print(
        Panel(
            Text.from_markup("  •  ".join(parts) if parts else "No findings", justify="center"),
            title="[bold #C0C0C0]Summary[/]",
            border_style="#606060",
        )
    )
    console.print()


def run_modules(names: list[str]) -> list[SectionResult]:
    results = []
    for i, name in enumerate(names, 1):
        cls = MODULES[name]
        with console.status(f"[bold #A0A0A0][{i}/{len(names)}] {name}…[/]", spinner="dots"):
            res = cls().run()
        results.append(res)
        render_section(res)
    return results


def show_scan_report(report: ScanReport) -> None:
    global last_scan
    last_scan = report
    table = Table(
        show_header=True,
        header_style="bold #C0C0C0",
        box=box.SIMPLE_HEAD,
        border_style="#505050",
        expand=True,
    )
    table.add_column("Sev", width=10)
    table.add_column("Kind", width=12)
    table.add_column("Path", style="#E0E0E0", ratio=3)
    table.add_column("Detail", style="#A0A0A0", ratio=2)

    style_map = {
        "critical": "bold red",
        "warn": "bold yellow",
        "info": "cyan",
    }
    for f in report.findings[:100]:
        table.add_row(
            Text(f.severity.upper(), style=style_map.get(f.severity, "")),
            f.kind,
            f.path,
            f.detail,
        )

    console.print(
        Panel(
            table if report.findings else Text("No threats or heuristics fired.", style="green"),
            title="[bold #C0C0C0]File scan findings[/]",
            border_style="#606060",
        )
    )
    meta = (
        f"files={report.files_seen}  hashed={report.files_hashed}  "
        f"denied={len(report.permission_denied)}  "
        f"clamav={'yes' if report.clamav_used else 'no'}  "
        f"time={report.duration_sec:.1f}s"
    )
    console.print(Align.center(Text(meta, style="dim #808080")))
    console.print()
    if report.permission_denied:
        console.print(
            f"[yellow]{len(report.permission_denied)} paths not readable without elevated privileges.[/]"
        )
        console.print("[dim]Re-run files and answer y when prompted to use sudo for samples.[/]\n")


def ask_sudo_for_path(path: str) -> bool:
    try:
        return Confirm.ask(
            f"[bold #C0C0C0]Scan this protected file with sudo?[/]\n  {path}",
            default=False,
        )
    except Exception:
        return False


def get_sudo_password() -> str | None:
    try:
        pw = getpass.getpass("sudo password (not stored): ")
        return pw if pw else None
    except Exception:
        return None


def cmd_help() -> None:
    console.print(
        Panel(
            "\n".join(
                f"  [bold]{c}[/]  — {n}: {d}" for c, n, d in FEATURES
            ),
            title="[bold #C0C0C0]Commands[/]",
            border_style="#606060",
        )
    )
    console.print(
        "[dim]Also: type a path to scan one file, e.g. /etc/passwd[/]\n"
    )


def cmd_full() -> None:
    global last_results
    last_results = run_modules(list(MODULES.keys()))
    summary_sections(last_results)
    # also deep file pass
    console.rule("[bold #A0A0A0]Deep file pass[/]", style="#505050")
    report = deep_scan(
        console,
        use_clam=_clamscan_available(),
        ask_sudo=ask_sudo_for_path,
        get_password=get_sudo_password,
    )
    show_scan_report(report)


def cmd_quick() -> None:
    global last_results
    last_results = run_modules(["system", "resources", "services"])
    summary_sections(last_results)


def cmd_security() -> None:
    global last_results
    last_results = run_modules(["security", "hardening", "rootkit_ind", "users", "packages", "filesystem"])
    summary_sections(last_results)


def cmd_files() -> None:
    report = deep_scan(
        console,
        use_clam=False,
        ask_sudo=ask_sudo_for_path,
        get_password=get_sudo_password,
    )
    show_scan_report(report)


def cmd_malware() -> None:
    clam = _clamscan_available()
    if clam:
        console.print("[green]ClamAV detected — using clamscan/clamdscan where possible.[/]")
    else:
        console.print(
            "[yellow]ClamAV not installed — using heuristic scan only.[/]\n"
            "[dim]Install: sudo pacman -S clamav && sudo freshclam[/]"
        )
    report = deep_scan(
        console,
        use_clam=clam,
        ask_sudo=ask_sudo_for_path,
        get_password=get_sudo_password,
    )
    show_scan_report(report)


def cmd_fim() -> None:
    console.print("[bold #C0C0C0]FIM ( integrity)[/]")
    choice = Prompt.ask(
        "Action",
        choices=["build", "check", "b", "c"],
        default="check",
    ).lower()
    if choice in ("build", "b"):
        n = build_baseline(console)
        console.print(f"[green]Baseline saved ({n} files) → ~/.local/share/aries/fim_baseline.json[/]\n")
    else:
        findings = compare_baseline(console)
        if not findings:
            console.print("[green]No changes vs baseline (or no baseline).[/]\n")
            return
        table = Table(show_header=True, header_style="bold #C0C0C0", box=box.SIMPLE_HEAD)
        table.add_column("Kind")
        table.add_column("Path")
        table.add_column("Detail")
        for f in findings[:80]:
            table.add_row(f.kind, f.path, f.detail)
        console.print(Panel(table, title="[bold #C0C0C0]Integrity changes[/]", border_style="#606060"))
        console.print()


def cmd_export() -> None:
    if not last_results and not last_scan:
        console.print("[yellow]Nothing to export yet.[/]\n")
        return
    path = Prompt.ask("Save JSON to", default="aries-report.json")
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
            for r in last_results
        ],
    }
    if last_scan:
        data["file_scan"] = {
            "files_seen": last_scan.files_seen,
            "files_hashed": last_scan.files_hashed,
            "denied": last_scan.permission_denied[:200],
            "clamav": last_scan.clamav_used,
            "findings": [
                {"path": f.path, "kind": f.kind, "detail": f.detail, "severity": f.severity}
                for f in last_scan.findings
            ],
        }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        console.print(f"[green]Saved → {path}[/]\n")
    except OSError as exc:
        console.print(f"[red]Failed: {exc}[/]\n")


def scan_single_file(path: str) -> None:
    from aries.scanner import scan_path, _clamscan_available

    console.print(f"[bold #A0A0A0]Scanning single path:[/] {path}")
    if not os.path.exists(path):
        console.print("[red]Path does not exist.[/]\n")
        return
    try:
        findings = scan_path(path, use_clam=_clamscan_available(), console=console)
    except PermissionError:
        if ask_sudo_for_path(path):
            # force content read via sudo for heuristics only
            from aries.scanner import read_with_optional_sudo, SUSPICIOUS_CONTENT

            data = read_with_optional_sudo(
                path, console, lambda p: True, get_sudo_password
            )
            findings = []
            if data:
                import re as _re

                for rx in SUSPICIOUS_CONTENT:
                    if rx.search(data):
                        from aries.scanner import ScanFinding

                        findings.append(
                            ScanFinding(path, "heuristic", "match via sudo read", "warn")
                        )
        else:
            findings = []
            console.print("[dim]Skipped.[/]\n")
            return

    if not findings:
        console.print("[green]Clean (no heuristic/ClamAV hits).[/]\n")
    else:
        for f in findings:
            console.print(f"[yellow]{f.kind}[/] {f.path}: {f.detail}")
        console.print()


# need os for single file
import os


def dispatch(raw: str) -> bool:
    """Return False to quit."""
    global last_results
    line = raw.strip()
    if not line:
        return True

    # path to scan
    if line.startswith("/") or line.startswith("~"):
        path = os.path.expanduser(line)
        scan_single_file(path)
        return True

    key = ALIASES.get(line.lower())
    if key is None:
        console.print(f"[yellow]Unknown command:[/] {line}  — type [bold]help[/]\n")
        return True

    if key == "quit":
        return False
    if key == "help":
        cmd_help()
    elif key == "full":
        cmd_full()
    elif key == "quick":
        cmd_quick()
    elif key == "security":
        cmd_security()
    elif key == "files":
        cmd_files()
    elif key == "malware":
        cmd_malware()
    elif key == "fim":
        cmd_fim()
    elif key == "system":
        last_results = run_modules(["system"])
        summary_sections(last_results)
    elif key == "packages":
        last_results = run_modules(["packages"])
        summary_sections(last_results)
    elif key == "export":
        cmd_export()
    elif key == "rootkit":
        show_tool_result(console, run_chkrootkit(console))
        show_tool_result(console, run_rkhunter(console))
    elif key == "hardening":
        last_results = run_modules(["hardening"])
        summary_sections(last_results)
    elif key == "logs":
        last_results = run_modules(["logs"])
        summary_sections(last_results)
    elif key == "lynis":
        show_tool_result(console, run_lynis(console), max_lines=120)
    return True


def chat_loop() -> None:
    prompt_install_missing(console)
    render_dashboard(console)
    while True:
        try:
            raw = Prompt.ask("[bold #C0C0C0]aries[/]")
        except (EOFError, KeyboardInterrupt):
            console.print()
            break
        if not dispatch(raw):
            console.print(Align.center(Text("ARIES out. Stay secure.", style="dim #808080")))
            console.print()
            break


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--quick", is_flag=True, help="Non-interactive quick scan")
@click.option("--json", "as_json", is_flag=True, help="JSON full module dump")
@click.option("--no-banner", is_flag=True, help="Skip dashboard")
@click.version_option(__version__, prog_name="ARIES")
def main(quick: bool, as_json: bool, no_banner: bool) -> None:
    """ARIES interactive auditor — type commands in the chat prompt."""
    if as_json:
        results = [cls().run() for cls in MODULES.values()]
        data = {
            "tool": "ARIES",
            "version": __version__,
            "sections": [
                {
                    "name": r.name,
                    "findings": [
                        {
                            "title": f.title,
                            "status": f.status.value,
                            "detail": f.detail,
                        }
                        for f in r.findings
                    ],
                }
                for r in results
            ],
        }
        print(json.dumps(data, indent=2))
        return

    if quick:
        if not no_banner:
            render_dashboard(console)
        cmd_quick()
        return

    try:
        chat_loop()
    except KeyboardInterrupt:
        console.print("\n")
        console.print(Align.center(Text("Interrupted.", style="dim #808080")))


if __name__ == "__main__":
    main()
