"""Users & privilege checks."""

from __future__ import annotations

import os
from pathlib import Path

from .base import SectionResult, Severity, read_file, run_cmd


class Users:
    name = "Users"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)

        # UID 0 accounts
        passwd = read_file("/etc/passwd") or ""
        uid0 = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0":
                uid0.append(parts[0])
        if uid0 == ["root"]:
            res.add("UID 0 accounts", Severity.OK, "only root")
        elif "root" in uid0 and len(uid0) > 1:
            others = [u for u in uid0 if u != "root"]
            res.add(
                "UID 0 accounts",
                Severity.CRITICAL,
                f"extra: {', '.join(others)}",
                recommendation="Investigate non-root UID 0 accounts",
            )
        else:
            res.add("UID 0 accounts", Severity.WARN, str(uid0))

        # Users with empty password (shadow)
        if os.geteuid() == 0:
            shadow = read_file("/etc/shadow") or ""
            empty = []
            for line in shadow.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] == "":
                    empty.append(parts[0])
            if empty:
                res.add(
                    "Empty password accounts",
                    Severity.CRITICAL,
                    ", ".join(empty),
                    recommendation="Lock or set passwords immediately",
                )
            else:
                res.add("Empty password accounts", Severity.OK, "none")
        else:
            res.add("Empty password accounts", Severity.SKIP, "requires root")

        # Sudo group members (rough)
        code, out, _ = run_cmd(["getent", "group", "sudo", "wheel"])
        if code == 0 and out:
            members = []
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 4 and parts[3]:
                    members.extend(parts[3].split(","))
            members = sorted(set(m for m in members if m))
            res.add(
                "Sudo/wheel members",
                Severity.INFO,
                ", ".join(members) if members else "none listed",
            )
        else:
            res.add("Sudo/wheel members", Severity.SKIP, "could not query")

        # Home directories world-writable?
        homes = Path("/home")
        if homes.is_dir():
            bad = []
            try:
                for entry in homes.iterdir():
                    if entry.is_dir():
                        mode = entry.stat().st_mode & 0o777
                        if mode & 0o002:  # world writable
                            bad.append(str(entry))
            except PermissionError:
                pass
            if bad:
                res.add(
                    "World-writable homes",
                    Severity.WARN,
                    ", ".join(bad),
                    recommendation="chmod o-w on those directories",
                )
            else:
                res.add("World-writable homes", Severity.OK, "none")

        return res
