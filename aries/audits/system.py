"""System information audit."""

from __future__ import annotations

import os
import platform
import socket
import time
from datetime import timedelta

from .base import SectionResult, Severity, run_cmd, read_file


class SystemInfo:
    name = "System"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)

        # Hostname
        hostname = socket.gethostname()
        res.add("Hostname", Severity.INFO, hostname)
        res.raw["hostname"] = hostname

        # OS / Arch
        os_release = {}
        content = read_file("/etc/os-release") or ""
        for line in content.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                os_release[k] = v.strip().strip('"')

        pretty = os_release.get("PRETTY_NAME", platform.system())
        res.add("Distribution", Severity.INFO, pretty)
        res.raw["os"] = pretty

        # Kernel
        kernel = platform.release()
        res.add("Kernel", Severity.INFO, kernel)
        res.raw["kernel"] = kernel

        # Architecture
        arch = platform.machine()
        res.add("Architecture", Severity.INFO, arch)
        res.raw["arch"] = arch

        # Uptime
        try:
            with open("/proc/uptime") as f:
                uptime_sec = float(f.read().split()[0])
            uptime = str(timedelta(seconds=int(uptime_sec)))
            res.add("Uptime", Severity.INFO, uptime)
            res.raw["uptime"] = uptime
        except Exception:
            res.add("Uptime", Severity.SKIP, "unavailable")

        # Boot time / systemd
        code, out, _ = run_cmd(["systemctl", "is-system-running"])
        if code == 0:
            status = out or "unknown"
            sev = Severity.OK if status == "running" else Severity.WARN
            res.add("Systemd state", sev, status)
        else:
            res.add("Systemd state", Severity.SKIP, "not available")

        # Is Arch?
        if "arch" in pretty.lower() or os_release.get("ID") == "arch":
            res.add("Arch Linux", Severity.OK, "detected")
        else:
            res.add("Arch Linux", Severity.WARN, "not detected (some checks may differ)")

        # Running as root?
        if os.geteuid() == 0:
            res.add("Privilege", Severity.INFO, "running as root (full visibility)")
        else:
            res.add(
                "Privilege",
                Severity.WARN,
                "running as user — some checks limited",
                recommendation="Re-run with sudo for complete results",
            )

        return res
