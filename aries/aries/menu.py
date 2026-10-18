"""j/k interactive menu with glowing selection."""

from __future__ import annotations

import select
import sys
import termios
import tty
from typing import Sequence

from rich.console import Console, Group
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich import box
from rich.table import Table
from rich.live import Live


def _flush_stdin() -> None:
    """Discard pending keystrokes."""
    try:
        fd = sys.stdin.fileno()
        if not sys.stdin.isatty():
            return
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                r, _, _ = select.select([fd], [], [], 0)
                if not r:
                    break
                sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        pass


def _read_key() -> str:
    """
    Blocking key read.
    Navigation: j/J = down, k/K = up
    Enter = select, q = quit
    Arrow keys and other ESC sequences are ignored (drained).
    """
    fd = sys.stdin.fileno()

    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        return "q" if not line else "enter"

    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        select.select([fd], [], [])
        ch = sys.stdin.read(1)

        # Drain ESC sequences (arrows, etc.) — do not use them for navigation
        if ch == "\x1b":
            while select.select([fd], [], [], 0.05)[0]:
                sys.stdin.read(1)
            return "ignore"

        if ch in ("\r", "\n"):
            return "enter"
        if ch in ("q", "Q", "\x03"):
            return "q"
        if ch in ("k", "K"):
            return "up"
        if ch in ("j", "J"):
            return "down"
        return "ignore"
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _build_panel(
    title: str,
    options: Sequence[tuple[str, str]],
    index: int,
    hint: str,
) -> Panel:
    table = Table(
        show_header=False,
        box=None,
        expand=False,
        padding=(0, 1),
        show_edge=False,
    )
    table.add_column(width=4, justify="center")
    table.add_column(min_width=28)
    table.add_column(style="dim #707070")

    for i, (label, desc) in enumerate(options):
        if i == index:
            pointer = Text("❯", style="bold #FFFFFF")
            name = Text(f" {label} ", style="bold #FFFFFF on #404040")
            detail = Text(desc, style="bold #C0C0C0")
        else:
            pointer = Text(" ", style="dim")
            name = Text(f" {label} ", style="#909090")
            detail = Text(desc, style="dim #606060")
        table.add_row(pointer, name, detail)

    # Clear, prominent controls line
    controls = Text()
    controls.append("  [ ", style="dim #606060")
    controls.append("j", style="bold #FFFFFF")
    controls.append(" down  ", style="#A0A0A0")
    controls.append("k", style="bold #FFFFFF")
    controls.append(" up  ", style="#A0A0A0")
    controls.append("Enter", style="bold #FFFFFF")
    controls.append(" select  ", style="#A0A0A0")
    controls.append("q", style="bold #FFFFFF")
    controls.append(" quit ", style="#A0A0A0")
    controls.append("]  ", style="dim #606060")

    return Panel(
        Group(
            Align.center(table),
            Text(""),
            Align.center(controls),
            Align.center(Text(hint, style="dim #707070")) if hint else Text(""),
        ),
        title=f"[bold #C0C0C0]{title}[/]",
        border_style="#606060",
        padding=(1, 2),
        box=box.ROUNDED,
    )


def arrow_menu(
    console: Console,
    title: str,
    options: Sequence[tuple[str, str]],
    *,
    hint: str = "Use j to move down, k to move up",
) -> int | None:
    """
    j/k menu with glowing selection.
    Redraws in-place via Live (only on keypress).
    """
    if not options:
        return None

    index = 0
    n = len(options)

    _flush_stdin()

    with Live(
        _build_panel(title, options, index, hint),
        console=console,
        auto_refresh=False,
        transient=True,
        redirect_stdout=False,
        redirect_stderr=False,
    ) as live:
        while True:
            key = _read_key()

            if key == "up":
                index = (index - 1) % n
                live.update(_build_panel(title, options, index, hint), refresh=True)
            elif key == "down":
                index = (index + 1) % n
                live.update(_build_panel(title, options, index, hint), refresh=True)
            elif key == "enter":
                _flush_stdin()
                return index
            elif key == "q":
                _flush_stdin()
                return None
            # ignore everything else


def arrow_menu_simple(
    console: Console,
    title: str,
    labels: Sequence[str],
) -> int | None:
    opts = [(lab, "") for lab in labels]
    return arrow_menu(console, title, opts)
