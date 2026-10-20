"""Detect optional tools and offer to install them (Arch Linux)."""

from __future__ import annotations

import shutil
import subprocess
import sys
import threading
import time

from rich.console import Console, Group

try:
    from aries.platform import detect_os, is_linux
except Exception:
    def detect_os():
        return "linux"
    def is_linux():
        return True
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm
from rich.text import Text
from rich.align import Align
from rich import box


# (binary name, pacman package, short description)
OPTIONAL_TOOLS = [
    ("lynis", "lynis", "system auditing and hardening checks"),
    ("chkrootkit", "chkrootkit", "local rootkit indicator scanner"),
    ("rkhunter", "rkhunter", "rootkit hunter"),
    ("clamscan", "clamav", "antivirus scanner (run freshclam after install)"),
]

# Frames for install animation
_SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_GOAT_FRAMES = [
    "◐  installing  ···",
    "◓  installing  ··•",
    "◑  installing  ·•·",
    "◒  installing  •··",
]


def missing_tools() -> list[tuple[str, str, str]]:
    return [(b, pkg, desc) for b, pkg, desc in OPTIONAL_TOOLS if not shutil.which(b)]


def _which_sudo() -> str | None:
    return shutil.which("sudo")


def _which_pacman() -> str | None:
    return shutil.which("pacman")


def _render_anim(frame_i: int, packages: list[str], phase: str) -> Panel:
    spin = _SPINNER[frame_i % len(_SPINNER)]
    goat = _GOAT_FRAMES[frame_i % len(_GOAT_FRAMES)]
    body = Text()
    body.append(f"  {spin}  ", style="bold #E0E0E0")
    body.append(goat + "\n\n", style="#A0A0A0")
    body.append("  packages: ", style="dim")
    body.append(", ".join(packages) + "\n", style="bold #C0C0C0")
    body.append(f"  status:   {phase}\n", style="dim #808080")
    body.append("\n  ", style="")
    # progress bar illusion
    width = 28
    pos = frame_i % (width + 1)
    bar = "█" * pos + "░" * (width - pos)
    body.append(bar, style="bold #909090")
    return Panel(
        Align.left(body),
        title="[bold #C0C0C0]ARIES · package install[/]",
        border_style="#606060",
        box=box.ROUNDED,
        padding=(1, 2),
    )


def _run_pacman_with_animation(console: Console, packages: list[str]) -> int:
    """
    Run pacman install with a live animation panel.
    Uses a real TTY for sudo password so authentication works.
    """
    sudo = _which_sudo()
    pacman = _which_pacman()
    if not pacman:
        console.print("[red]pacman not found. This installer targets Arch Linux.[/]")
        return 1
    if not sudo:
        console.print("[red]sudo not found. Install packages as root manually.[/]")
        return 1

    # 1) Refresh sudo credential with visible password prompt on the real TTY
    console.print(
        "[bold #C0C0C0]Sudo authentication required[/] — enter your password if asked.\n"
    )
    try:
        auth = subprocess.run(
            [sudo, "-v"],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
    except Exception as exc:
        console.print(f"[red]sudo failed:[/] {exc}")
        return 1

    if auth.returncode != 0:
        console.print(
            "[red]Sudo authentication failed.[/] "
            "Try again or install manually:\n"
            f"  [bold]sudo pacman -S --needed {' '.join(packages)}[/]"
        )
        return auth.returncode

    # 2) Run pacman while showing animation (capture output, stream after)
    cmd = [sudo, "-n", "pacman", "-S", "--needed", "--noconfirm", *packages]
    # -n: non-interactive sudo (credential already cached via -v)

    result: dict = {"code": 1, "out": "", "err": ""}
    done = threading.Event()

    def worker() -> None:
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
            result["code"] = r.returncode
            result["out"] = r.stdout or ""
            result["err"] = r.stderr or ""
        except Exception as exc:
            result["code"] = 1
            result["err"] = str(exc)
        finally:
            done.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    frame = 0
    with Live(
        _render_anim(frame, packages, "downloading / installing…"),
        console=console,
        refresh_per_second=12,
        transient=True,
    ) as live:
        while not done.is_set():
            frame += 1
            phase = "resolving dependencies…" if frame < 15 else "installing packages…"
            live.update(_render_anim(frame, packages, phase))
            time.sleep(0.08)
        live.update(_render_anim(frame, packages, "finishing…"))

    thread.join(timeout=2)

    # Show pacman output (last lines)
    combined = (result["out"] + "\n" + result["err"]).strip()
    if combined:
        lines = combined.splitlines()
        tail = lines[-20:] if len(lines) > 20 else lines
        console.print(
            Panel(
                Text("\n".join(tail), style="#A0A0A0"),
                title="[bold #C0C0C0]pacman output[/]",
                border_style="#505050",
            )
        )

    return int(result["code"])


def prompt_install_missing(console: Console) -> None:
    """
    On startup: list missing tools and ask whether to install via pacman.
    """
    if not is_linux():
        kind = detect_os()
        console.print(
            Panel(
                Text(
                    f"Host OS: {kind}. Automatic package install is supported on Arch Linux (pacman).\n"
                    "Optional tools: install ClamAV / OS security updates with your platform package manager.",
                    style="#A0A0A0",
                ),
                title="[bold #C0C0C0]Dependencies[/]",
                border_style="#505050",
            )
        )
        console.print()
        return

    missing = missing_tools()
    if not missing:
        console.print(
            Panel(
                Text(
                    "Optional tools: lynis, chkrootkit, rkhunter, clamav — all found.",
                    style="green",
                ),
                border_style="#505050",
                title="[bold #C0C0C0]Dependencies[/]",
            )
        )
        console.print()
        return

    if not _which_pacman():
        console.print(
            Panel(
                Text(
                    "Optional tools missing, but pacman was not found.\n"
                    "Install lynis / chkrootkit / rkhunter / clamav with your package manager.",
                    style="yellow",
                ),
                title="[bold #C0C0C0]Optional tools[/]",
                border_style="#606060",
            )
        )
        console.print()
        return

    lines = ["These optional tools are not installed:\n"]
    for binary, pkg, desc in missing:
        lines.append(f"  • [bold]{pkg}[/] ([cyan]{binary}[/]) — {desc}")
    lines.append("")
    lines.append(
        "ARIES works without them; they unlock [bold]lynis[/], [bold]rootkit[/], "
        "and stronger [bold]malware[/] scans."
    )
    lines.append(
        "[dim]Note: chkrootkit may be AUR-only on some Arch setups; "
        "pacman will skip packages it cannot find.[/]"
    )

    console.print(
        Panel(
            Text.from_markup("\n".join(lines)),
            title="[bold #C0C0C0]Optional tools missing[/]",
            border_style="#606060",
        )
    )

    try:
        if not Confirm.ask("Install missing packages with pacman now?", default=False):
            console.print(
                "[dim]Skipped. Later: sudo pacman -S lynis rkhunter clamav[/]\n"
            )
            return
    except Exception:
        return

    packages = sorted({pkg for _, pkg, _ in missing})
    code = _run_pacman_with_animation(console, packages)

    if code == 0:
        console.print("[green]Install finished.[/]")
        still = missing_tools()
        if still:
            names = ", ".join(b for b, _, _ in still)
            console.print(
                f"[yellow]Still missing:[/] {names}\n"
                "[dim]Some packages may only be on the AUR "
                "(e.g. chkrootkit → yay -S chkrootkit). "
                "For clamav run: sudo freshclam[/]"
            )
        else:
            console.print("[green]All optional tools are available.[/]")
    else:
        console.print(
            f"[red]Install exited with code {code}.[/]\n"
            "Try manually:\n"
            f"  [bold]sudo pacman -S --needed {' '.join(packages)}[/]\n"
            "If a package is missing from repos, use AUR (yay/paru)."
        )
    console.print()
