"""
Rootkit / compromise indicators (original Python).

Looks for well-known suspicious paths, process name tricks, and local
anomalies in the same spirit as classic rootkit hunters — without copying
their source. Safe, read-only checks.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .base import SectionResult, Severity, run_cmd

# Paths historically associated with common rootkits / backdoors (public knowledge)
SUSPICIOUS_PATHS = [
    "/dev/shm/.X11-unix",
    "/dev/.lib",
    "/dev/.static",
    "/dev/.udev",
    "/usr/bin/...",
    "/usr/sbin/...",
    "/tmp/.../",
    "/var/tmp/...",
    "/etc/rc.d/init.d/.../",
    "/lib/.x",
    "/lib64/.x",
]

SUSPICIOUS_NAMES = re.compile(
    r"^(mine|xmrig|kdevtmpfs|ksoftirqds|\[kworker/0:0\])$",
    re.I,
)

# Known default webshell / implant filenames (public IOCs, short list)
BAD_BASENAMES = {
    "c99.php",
    "r57.php",
    "shell.php",
    "wso.php",
    "b374k.php",
    "xmrig",
    "kinsing",
}


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
        for p in SUSPICIOUS_PATHS:
            if os.path.lexists(p):
                hits.append(p)
        if hits:
            res.add(
                "Suspicious paths",
                Severity.WARN,
                ", ".join(hits[:8]),
                "Investigate unexpected hidden paths",
            )
            res.raw["suspicious_paths"] = hits
        else:
            res.add("Suspicious paths", Severity.OK, "none of the common indicator paths present")

    def _proc(self, res: SectionResult) -> None:
        weird = []
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    comm = Path(f"/proc/{pid}/comm").read_text().strip()
                except OSError:
                    continue
                if SUSPICIOUS_NAMES.match(comm):
                    weird.append(f"{pid}:{comm}")
                # empty comm or pure spaces
                if not comm.strip():
                    weird.append(f"{pid}:<empty>")
        except OSError:
            res.add("Process names", Severity.SKIP, "cannot list /proc")
            return
        if weird:
            res.add("Suspicious process names", Severity.WARN, ", ".join(weird[:10]))
        else:
            res.add("Suspicious process names", Severity.OK, "no matches in short IOC list")

    def _modules(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(["lsmod"])
        if code != 0 or not out:
            res.add("Kernel modules", Severity.SKIP, "lsmod unavailable")
            return
        lines = [L.split()[0] for L in out.splitlines()[1:] if L.strip()]
        res.add("Kernel modules", Severity.INFO, f"{len(lines)} loaded")
        # hide-style names
        hidden_style = [m for m in lines if m.startswith("hide") or m in ("reptile", "diamorphine")]
        if hidden_style:
            res.add("Suspicious module names", Severity.CRITICAL, ", ".join(hidden_style))
        else:
            res.add("Suspicious module names", Severity.OK, "none matched short list")

    def _promiscuous(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(["ip", "-o", "link"])
        if code != 0:
            res.add("Promiscuous interfaces", Severity.SKIP, "ip unavailable")
            return
        promisc = [L for L in out.splitlines() if "PROMISC" in L]
        if promisc:
            res.add(
                "Promiscuous interfaces",
                Severity.WARN,
                f"{len(promisc)} interface(s) PROMISC",
                "Expected for some sniffers; review if unexpected",
            )
        else:
            res.add("Promiscuous interfaces", Severity.OK, "none")

    def _tmpdir(self, res: SectionResult) -> None:
        hits = []
        for root in ("/tmp", "/var/tmp", "/dev/shm"):
            if not os.path.isdir(root):
                continue
            try:
                for name in os.listdir(root):
                    if name.lower() in BAD_BASENAMES or name.startswith("."):
                        # only flag hidden if executable
                        path = os.path.join(root, name)
                        try:
                            st = os.lstat(path)
                            if name.lower() in BAD_BASENAMES:
                                hits.append(path)
                            elif st.st_mode & 0o111 and name.startswith("."):
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
                "Run: rootkit / lynis / malware from the ARIES prompt",
            )
        else:
            res.add(
                "External tools installed",
                Severity.INFO,
                "none (optional: clamav lynis rkhunter chkrootkit)",
            )
