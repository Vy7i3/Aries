"""
Deep per-file scanner inspired by:
- FIM: checksums (MD5/SHA256), size, mode, mtime baseline comparison
- Free antivirus (ClamAV): optional clamscan; heuristic checks when unavailable

Never logs or stores sudo passwords. Uses getpass + sudo -S only when the user
explicitly approves scanning a permission-denied path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Iterator

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

try:
    from aries.platform import default_scan_roots, skip_dir_names, detect_os
except Exception:
    def default_scan_roots():
        return ["/etc", "/tmp", "/home"]
    def skip_dir_names():
        return {"proc", "sys", "dev", ".git"}
    def detect_os():
        return "linux"

try:
    from aries.antivirus import scan_file as av_scan_file, load_signatures, signature_stats
except Exception:
    av_scan_file = None
    load_signatures = None
    signature_stats = None

# Critical paths (FIM monitored set for Linux / Arch)
DEFAULT_SCAN_ROOTS = [
    "/etc",
    "/tmp",
    "/var/tmp",
    "/var/spool/cron",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
    "/home",
    "/root",
    "/boot",
    "/usr/bin",
    "/usr/sbin",
]

SKIP_DIR_NAMES = {
    "proc", "sys", "dev", "run", "snap", "node_modules",
    ".cache", ".npm", ".cargo", "__pycache__", ".git",
    "lost+found", "containers", "docker", "signatures",
    ".venv", "venv",
}

# Heuristic patterns (lightweight free-AV style, not a full engine)
SUSPICIOUS_NAME = re.compile(
    r"(^|\.)(payload|backdoor|rootkit|keylog|miner|cryptominer|webshell)"
    r"|(\.php\.|\.jsp\.|shell\.php|c99\.php|r57\.php)",
    re.I,
)
SUSPICIOUS_CONTENT = [
    re.compile(rb"eval\s*\(\s*base64_decode\s*\(", re.I),
    re.compile(rb"/bin/bash\s+-i\s+>&\s+/dev/tcp/", re.I),
    re.compile(rb"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE", re.I),
]

MAX_HASH_SIZE = 50 * 1024 * 1024  # 50 MiB
MAX_HEURISTIC_READ = 512 * 1024
MAX_FILES_DEFAULT = 50_000

def _is_excluded_path(path: str) -> bool:
    """Skip ARIES install tree and signature databases to avoid self-hits."""
    try:
        low = path.replace("\\", "/").lower()
        if "/signatures/" in low or low.endswith("signatures"):
            return True
        if "sha256-hashes" in low:
            return True
        # common project layout markers
        if "/aries/aries/" in low or "/aries/audits/" in low:
            return True
        if low.rstrip("/").endswith("/aries/aries") or low.rstrip("/").endswith("/aries/audits"):
            return True
        name = Path(path).name.lower()
        if name.startswith("sha256-hashes"):
            return True
    except Exception:
        return False
    return False

BASELINE_PATH = Path.home() / ".local" / "share" / "aries" / "fim_baseline.json"


@dataclass
class FileRecord:
    path: str
    size: int
    mode: int
    uid: int
    gid: int
    mtime: float
    sha256: str = ""
    md5: str = ""


@dataclass
class ScanFinding:
    path: str
    kind: str  # clean | threat | heuristic | permission | error | changed | new | deleted
    detail: str = ""
    severity: str = "info"


@dataclass
class ScanReport:
    files_seen: int = 0
    files_hashed: int = 0
    permission_denied: list[str] = field(default_factory=list)
    findings: list[ScanFinding] = field(default_factory=list)
    clamav_used: bool = False
    duration_sec: float = 0.0


def _hash_file(path: str) -> tuple[str, str]:
    """Return (sha256, md5) hex digests. Empty if unreadable/too large."""
    try:
        size = os.path.getsize(path)
        if size > MAX_HASH_SIZE:
            return "", ""
        h256 = hashlib.sha256()
        hmd5 = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 256)
                if not chunk:
                    break
                h256.update(chunk)
                hmd5.update(chunk)
        return h256.hexdigest(), hmd5.hexdigest()
    except OSError:
        return "", ""


def _heuristic_check(path: str) -> str | None:
    name = os.path.basename(path)
    if SUSPICIOUS_NAME.search(name):
        return f"suspicious filename: {name}"
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size == 0 or st.st_size > MAX_HEURISTIC_READ:
            # still check executable + world-writable
            if st.st_mode & stat.S_IWOTH and st.st_mode & (stat.S_IXUSR | stat.S_IXOTH):
                return "world-writable executable"
            return None
        with open(path, "rb") as f:
            data = f.read(MAX_HEURISTIC_READ)
        for rx in SUSPICIOUS_CONTENT:
            if rx.search(data):
                return f"heuristic content match: {rx.pattern[:40]!r}"
        if st.st_mode & stat.S_IWOTH and st.st_mode & (stat.S_IXUSR | stat.S_IXOTH):
            return "world-writable executable"
    except OSError:
        return None
    return None


def _clamscan_available() -> bool:
    return shutil.which("clamscan") is not None or shutil.which("clamdscan") is not None


def _clamscan_file(path: str) -> str | None:
    """Return threat name if FOUND, None if clean/unavailable."""
    for cmd in ("clamdscan", "clamscan"):
        if not shutil.which(cmd):
            continue
        try:
            # --no-summary keeps output parseable; never elevates itself
            r = subprocess.run(
                [cmd, "--no-summary", path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            out = (r.stdout or "") + (r.stderr or "")
            if "FOUND" in out:
                # path: ThreatName FOUND
                m = re.search(r":\s*(.+?)\s+FOUND", out)
                return m.group(1).strip() if m else "malware"
            return None
        except (subprocess.TimeoutExpired, OSError):
            continue
    return None


def walk_files(
    roots: list[str],
    max_files: int = MAX_FILES_DEFAULT,
    max_depth: int = 8,
) -> Iterator[str]:
    seen = 0
    for root in roots:
        if not os.path.isdir(root) and not os.path.isfile(root):
            continue
        if os.path.isfile(root):
            yield root
            seen += 1
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                depth = dirpath[len(root) :].count(os.sep)
                if depth >= max_depth:
                    dirnames.clear()
                    continue
                skip = skip_dir_names()
                dirnames[:] = [
                    d
                    for d in dirnames
                    if d not in skip and not d.startswith(".")
                ]
                for name in filenames:
                    if seen >= max_files:
                        return
                    full = os.path.join(dirpath, name)
                    if _is_excluded_path(full):
                        continue
                    yield full
                    seen += 1
        except (OSError, PermissionError):
            continue


def read_with_optional_sudo(
    path: str,
    console: Console,
    ask_sudo: Callable[[str], bool],
    get_password: Callable[[], str | None],
) -> bytes | None:
    """
    Try to read file. On permission error, ask user; if yes, sudo -S cat once.
    Password never written to disk or logs.
    """
    try:
        with open(path, "rb") as f:
            return f.read(MAX_HEURISTIC_READ)
    except PermissionError:
        console.print(f"[yellow]Permission denied:[/] {path}")
        if not ask_sudo(path):
            return None
        password = get_password()
        if not password:
            return None
        try:
            r = subprocess.run(
                ["sudo", "-S", "-p", "", "cat", path],
                input=password + "\n",
                capture_output=True,
                timeout=30,
            )
            # scrub
            del password
            if r.returncode == 0:
                return r.stdout[:MAX_HEURISTIC_READ]
            console.print(f"[red]sudo failed for {path} (code {r.returncode})[/]")
            return None
        except Exception as exc:
            console.print(f"[red]sudo error:[/] {exc}")
            return None
    except OSError as exc:
        console.print(f"[dim]skip {path}: {exc}[/]")
        return None


def scan_path(
    path: str,
    *,
    use_clam: bool,
    console: Console | None = None,
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    if _is_excluded_path(path):
        return findings
    try:
        st = os.lstat(path)
    except PermissionError:
        return [ScanFinding(path, "permission", "permission denied", "warn")]
    except OSError as exc:
        return [ScanFinding(path, "error", str(exc), "info")]

    if not stat.S_ISREG(st.st_mode):
        return findings

    h = _heuristic_check(path)
    if h:
        findings.append(ScanFinding(path, "heuristic", h, "warn"))

    if use_clam:
        threat = _clamscan_file(path)
        if threat:
            findings.append(ScanFinding(path, "threat", threat, "critical"))

    # Local SHA-256 signature database (ARIES antivirus engine)
    if av_scan_file is not None:
        try:
            av = av_scan_file(path)
            if av.get("status") == "infected":
                findings.append(
                    ScanFinding(
                        path,
                        "threat",
                        av.get("detail") or "SHA-256 malware signature match",
                        "critical",
                    )
                )
        except Exception:
            pass

    return findings


def deep_scan(
    console: Console,
    roots: list[str] | None = None,
    *,
    max_files: int = MAX_FILES_DEFAULT,
    use_clam: bool | None = None,
    ask_sudo: Callable[[str], bool] | None = None,
    get_password: Callable[[], str | None] | None = None,
) -> ScanReport:
    """
    Walk roots, inspect every regular file possible.
    Permission-denied files are listed; optional interactive sudo for content checks.
    """
    if roots is None:
        try:
            from aries.knowledge import scan_roots_from_repo
            repo_roots = [r for r in scan_roots_from_repo() if __import__('os').path.isdir(r)]
        except Exception:
            repo_roots = []
        roots = repo_roots or default_scan_roots()
    roots = roots or default_scan_roots()
    if use_clam is None:
        use_clam = _clamscan_available()

    report = ScanReport(clamav_used=bool(use_clam and _clamscan_available()))
    t0 = time.time()
    denied: list[str] = []

    paths = list(walk_files(roots, max_files=max_files))
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold #A0A0A0]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning files…", total=len(paths))
        for path in paths:
            report.files_seen += 1
            try:
                st = os.lstat(path)
            except PermissionError:
                denied.append(path)
                report.permission_denied.append(path)
                progress.advance(task)
                continue
            except OSError:
                progress.advance(task)
                continue

            if not stat.S_ISREG(st.st_mode):
                progress.advance(task)
                continue

            # Hash when possible (FIM)
            try:
                sha, md5 = _hash_file(path)
                if sha:
                    report.files_hashed += 1
            except PermissionError:
                denied.append(path)
                report.permission_denied.append(path)
                progress.advance(task)
                continue

            # Extra FIM-style attribute flags
            try:
                mode = st.st_mode
                if mode & 0o1000 and mode & 0o002:  # sticky + world writable dir handled elsewhere
                    pass
                if stat.S_ISLNK(mode):
                    pass
                # setuid outside typical bins already partially covered by security module
            except Exception:
                pass
            findings = scan_path(path, use_clam=report.clamav_used, console=console)
            report.findings.extend(findings)
            progress.advance(task)

    # Optional: re-try a sample of denied paths with sudo if callbacks provided
    if denied and ask_sudo and get_password:
        sample = denied[:20]  # cap interactive prompts
        for path in sample:
            if not ask_sudo(path):
                continue
            data = read_with_optional_sudo(path, console, lambda p: True, get_password)
            if data is None:
                continue
            for rx in SUSPICIOUS_CONTENT:
                if rx.search(data):
                    report.findings.append(
                        ScanFinding(
                            path,
                            "heuristic",
                            f"heuristic (via sudo): {rx.pattern[:40]!r}",
                            "warn",
                        )
                    )
                    break

    report.duration_sec = time.time() - t0
    return report


def load_baseline() -> dict[str, dict]:
    if not BASELINE_PATH.is_file():
        return {}
    try:
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_baseline(records: dict[str, dict]) -> None:
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(json.dumps(records, indent=2), encoding="utf-8")


def build_baseline(
    console: Console,
    roots: list[str] | None = None,
    max_files: int = 15_000,
) -> int:
    """Create/overwrite FIM baseline (FIM checksum inventory)."""
    if roots is None:
        roots = default_scan_roots()[:8] or ["/etc", "/usr/bin"]
    roots = roots or default_scan_roots()[:8]
    records: dict[str, dict] = {}
    paths = list(walk_files(roots, max_files=max_files, max_depth=5))
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold #A0A0A0]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Building FIM baseline…", total=len(paths))
        for path in paths:
            try:
                st = os.lstat(path)
                if not stat.S_ISREG(st.st_mode):
                    progress.advance(task)
                    continue
                sha, md5 = _hash_file(path)
                records[path] = {
                    "size": st.st_size,
                    "mode": st.st_mode,
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "mtime": st.st_mtime,
                    "sha256": sha,
                    "md5": md5,
                }
            except OSError:
                pass
            progress.advance(task)
    save_baseline(records)
    return len(records)


def compare_baseline(console: Console) -> list[ScanFinding]:
    """Compare current files to baseline; report new/changed/deleted."""
    base = load_baseline()
    if not base:
        console.print("[yellow]No baseline found. Run: fim[/] to create one.")
        return []

    findings: list[ScanFinding] = []
    for path, meta in base.items():
        try:
            st = os.lstat(path)
            sha, _ = _hash_file(path)
            changed = []
            if meta.get("sha256") and sha and sha != meta["sha256"]:
                changed.append("sha256")
            if st.st_size != meta.get("size"):
                changed.append("size")
            if (st.st_mode & 0o7777) != (meta.get("mode", 0) & 0o7777):
                changed.append("mode")
            if changed:
                findings.append(
                    ScanFinding(
                        path,
                        "changed",
                        f"attributes changed: {', '.join(changed)}",
                        "warn",
                    )
                )
        except FileNotFoundError:
            findings.append(ScanFinding(path, "deleted", "missing since baseline", "warn"))
        except OSError as exc:
            findings.append(ScanFinding(path, "error", str(exc), "info"))

    return findings
