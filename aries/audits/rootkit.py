"""Rootkit / compromise indicators using ARIES knowledge repo."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .base import SectionResult, Severity, run_cmd

try:
    from aries.knowledge import (
        dangerous_paths,
        dangerous_basenames,
        dangerous_process_names,
        dangerous_modules,
    )
except Exception:
    dangerous_paths = lambda: []
    dangerous_basenames = lambda: set()
    dangerous_process_names = lambda: []
    dangerous_modules = lambda: set()


class RootkitIndicators:
    name = "Rootkit indicators"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)
        self._paths(res)
        self._proc(res)
        self._modules(res)
        self._promiscuous(res)
        self._tmpdir(res)
        self._external(res)
        return res

    def _paths(self, res: SectionResult) -> None:
        hits = []
        for p in dangerous_paths() or []:
            if os.path.lexists(p):
                hits.append(p)
        if hits:
            res.add(
                "Suspicious paths",
                Severity.WARN,
                ", ".join(hits[:8]),
                recommendation="Investigate unexpected hidden paths (see repo/dangerous_indicators.json)",
            )
            res.raw["suspicious_paths"] = hits
        else:
            res.add("Suspicious paths", Severity.OK, "none of the indicator paths present")

    def _proc(self, res: SectionResult) -> None:
        names = {n.lower() for n in (dangerous_process_names() or [])}
        weird = []
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    comm = Path(f"/proc/{pid}/comm").read_text().strip()
                except OSError:
                    continue
                if comm.lower() in names:
                    weird.append(f"{pid}:{comm}")
                if not comm.strip():
                    weird.append(f"{pid}:<empty>")
        except OSError:
            res.add("Process names", Severity.SKIP, "cannot list /proc")
            return
        if weird:
            res.add("Suspicious process names", Severity.WARN, ", ".join(weird[:10]))
        else:
            res.add("Suspicious process names", Severity.OK, "no matches in indicator list")

    def _modules(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(["lsmod"])
        if code != 0 or not out:
            res.add("Kernel modules", Severity.SKIP, "lsmod unavailable")
            return
        lines = [L.split()[0] for L in out.splitlines()[1:] if L.strip()]
        res.add("Kernel modules", Severity.INFO, f"{len(lines)} loaded")
        bad = dangerous_modules() or set()
        hidden_style = [m for m in lines if m.lower() in bad or m.lower().startswith("hide")]
        if hidden_style:
            res.add("Suspicious module names", Severity.CRITICAL, ", ".join(hidden_style))
        else:
            res.add("Suspicious module names", Severity.OK, "none matched indicator list")

    def _promiscuous(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(["ip", "-o", "link"])
        if code != 0:
            res.add("Promiscuous interfaces", Severity.SKIP, "ip unavailable")
            return
        promisc = [L for L in (out or "").splitlines() if "PROMISC" in L]
        if promisc:
            res.add(
                "Promiscuous interfaces",
                Severity.WARN,
                f"{len(promisc)} interface(s) PROMISC",
                recommendation="Expected for some sniffers; review if unexpected",
            )
        else:
            res.add("Promiscuous interfaces", Severity.OK, "none")

    def _tmpdir(self, res: SectionResult) -> None:
        bad = dangerous_basenames() or set()
        hits = []
        for root in ("/tmp", "/var/tmp", "/dev/shm"):
            if not os.path.isdir(root):
                continue
            try:
                for name in os.listdir(root):
                    path = os.path.join(root, name)
                    if name.lower() in bad:
                        hits.append(path)
                        continue
                    if name.startswith("."):
                        try:
                            st = os.lstat(path)
                            if st.st_mode & 0o111:
                                hits.append(path)
                        except OSError:
                            continue
            except OSError:
                continue
        if hits:
            res.add("Temp IOC filenames", Severity.WARN, ", ".join(hits[:8]))
        else:
            res.add("Temp IOC filenames", Severity.OK, "none in /tmp /var/tmp /dev/shm")

    def _external(self, res: SectionResult) -> None:
        import shutil

        present = []
        for tool in ("chkrootkit", "rkhunter", "lynis", "clamscan", "clamdscan"):
            if shutil.which(tool):
                present.append(tool)
        if present:
            res.add(
                "External tools installed",
                Severity.INFO,
                ", ".join(present),
                recommendation="Run: rootkit / lynis / malware from the ARIES prompt",
            )
        else:
            res.add(
                "External tools installed",
                Severity.INFO,
                "none (optional: clamav lynis rkhunter chkrootkit)",
            )
