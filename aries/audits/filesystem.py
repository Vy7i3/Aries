"""Real filesystem scanning for security-relevant files."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from .base import SectionResult, Severity


# Directories we actually walk (bounded, security-relevant)
SCAN_ROOTS = [
    "/etc",
    "/tmp",
    "/var/tmp",
    "/var/spool/cron",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
    "/home",
    "/root",
]

# Skip heavy / virtual trees
SKIP_DIRS = {
    "proc", "sys", "dev", "run", "snap", "boot",
    ".cache", ".npm", ".cargo", "node_modules",
    "__pycache__", ".git",
}

MAX_FILES = 25_000  # hard stop to keep audit responsive
MAX_DEPTH = 6


class Filesystem:
    name = "Filesystem"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)

        world_writable: list[str] = []
        suid_sgid: list[str] = []
        recent_etc: list[str] = []
        suspicious_tmp: list[str] = []
        no_owner: list[str] = []
        scanned = 0
        errors = 0

        now = time.time()
        recent_cutoff = now - 7 * 86400  # 7 days

        for root in SCAN_ROOTS:
            if not os.path.isdir(root):
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                    # prune
                    depth = dirpath[len(root):].count(os.sep)
                    if depth >= MAX_DEPTH:
                        dirnames.clear()
                        continue
                    dirnames[:] = [
                        d for d in dirnames
                        if d not in SKIP_DIRS and not d.startswith(".")
                    ]

                    for name in filenames:
                        if scanned >= MAX_FILES:
                            break
                        path = os.path.join(dirpath, name)
                        scanned += 1
                        try:
                            st = os.lstat(path)
                        except (OSError, PermissionError):
                            errors += 1
                            continue

                        mode = st.st_mode
                        if not stat.S_ISREG(mode):
                            continue

                        # World-writable regular files
                        if mode & stat.S_IWOTH:
                            world_writable.append(path)

                        # SUID / SGID
                        if mode & (stat.S_ISUID | stat.S_ISGID):
                            suid_sgid.append(path)

                        # Recently modified under /etc
                        if root == "/etc" and st.st_mtime >= recent_cutoff:
                            recent_etc.append(path)

                        # Executable or hidden scripts in /tmp
                        if root in ("/tmp", "/var/tmp"):
                            if name.startswith(".") or (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                                suspicious_tmp.append(path)

                        # Files with no owner (deleted user)
                        try:
                            if st.st_uid >= 65534 or st.st_gid >= 65534:
                                no_owner.append(path)
                        except Exception:
                            pass

                    if scanned >= MAX_FILES:
                        break
                if scanned >= MAX_FILES:
                    break
            except (OSError, PermissionError):
                errors += 1
                continue

        res.raw["files_scanned"] = scanned
        res.raw["scan_errors"] = errors

        res.add(
            "Files scanned",
            Severity.INFO,
            f"{scanned} files across {len(SCAN_ROOTS)} roots"
            + (f" (hit limit {MAX_FILES})" if scanned >= MAX_FILES else ""),
        )

        # World-writable
        if world_writable:
            sample = ", ".join(world_writable[:5])
            more = f" +{len(world_writable)-5} more" if len(world_writable) > 5 else ""
            res.add(
                "World-writable files",
                Severity.WARN if len(world_writable) < 20 else Severity.CRITICAL,
                f"{len(world_writable)} found • {sample}{more}",
                recommendation="Review and chmod o-w on unexpected paths",
            )
            res.raw["world_writable"] = world_writable[:50]
        else:
            res.add("World-writable files", Severity.OK, "none in scanned paths")

        # SUID/SGID outside expected dirs already partially covered; list extras
        if suid_sgid:
            res.add(
                "SUID/SGID files (scan)",
                Severity.INFO,
                f"{len(suid_sgid)} found in scan roots",
            )
            res.raw["suid_sgid"] = suid_sgid[:40]
        else:
            res.add("SUID/SGID files (scan)", Severity.OK, "none in scan roots")

        # Recent /etc changes
        if recent_etc:
            sample = ", ".join(os.path.basename(p) for p in recent_etc[:8])
            res.add(
                "Recent /etc changes (7d)",
                Severity.INFO,
                f"{len(recent_etc)} files • e.g. {sample}",
            )
            res.raw["recent_etc"] = recent_etc[:40]
        else:
            res.add("Recent /etc changes (7d)", Severity.OK, "none detected")

        # Suspicious tmp
        if suspicious_tmp:
            sample = ", ".join(suspicious_tmp[:5])
            res.add(
                "Suspicious /tmp files",
                Severity.WARN,
                f"{len(suspicious_tmp)} hidden or executable • {sample}",
                recommendation="Inspect /tmp and /var/tmp for unexpected scripts",
            )
            res.raw["suspicious_tmp"] = suspicious_tmp[:30]
        else:
            res.add("Suspicious /tmp files", Severity.OK, "none")

        # Orphan ownership
        if no_owner:
            res.add(
                "Unowned files",
                Severity.WARN,
                f"{len(no_owner)} with high/unknown UID/GID",
            )
        else:
            res.add("Unowned files", Severity.OK, "none detected")

        if errors:
            res.add("Scan errors", Severity.INFO, f"{errors} permission/IO errors (normal if non-root)")

        return res
