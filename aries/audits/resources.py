"""CPU / Memory / Disk resource audit."""

from __future__ import annotations

import psutil

from .base import SectionResult, Severity


class Resources:
    name = "Resources"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)

        # CPU
        cpu_count = psutil.cpu_count(logical=True) or 1
        cpu_pct = psutil.cpu_percent(interval=0.4)
        load1, load5, load15 = psutil.getloadavg()
        res.add(
            "CPU",
            Severity.OK if cpu_pct < 85 else Severity.WARN,
            f"{cpu_count} cores • {cpu_pct:.1f}% used • load {load1:.2f}/{load5:.2f}/{load15:.2f}",
        )
        res.raw["cpu_percent"] = cpu_pct
        res.raw["load"] = [load1, load5, load15]

        # Memory
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        mem_sev = Severity.OK
        if mem.percent > 90:
            mem_sev = Severity.CRITICAL
        elif mem.percent > 80:
            mem_sev = Severity.WARN
        res.add(
            "Memory",
            mem_sev,
            f"{mem.used // (1024**2)} / {mem.total // (1024**2)} MiB ({mem.percent:.1f}%)",
        )
        res.add(
            "Swap",
            Severity.OK if swap.percent < 50 else Severity.WARN,
            f"{swap.used // (1024**2)} / {swap.total // (1024**2)} MiB ({swap.percent:.1f}%)",
        )
        res.raw["memory"] = {"total": mem.total, "used": mem.used, "percent": mem.percent}
        res.raw["swap"] = {"total": swap.total, "used": swap.used, "percent": swap.percent}

        # Disks (root + common mount points)
        partitions = psutil.disk_partitions(all=False)
        seen = set()
        skip_fs = {
            "tmpfs", "devtmpfs", "squashfs", "overlay",
            "erofs", "proc", "sysfs", "cgroup", "cgroup2",
            "devpts", "securityfs", "pstore", "bpf", "tracefs",
            "debugfs", "hugetlbfs", "mqueue", "fusectl",
        }
        for part in partitions:
            if part.mountpoint in seen:
                continue
            if part.fstype in skip_fs:
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            if usage.total == 0:
                continue
            seen.add(part.mountpoint)
            sev = Severity.OK
            if usage.percent >= 95:
                sev = Severity.CRITICAL
            elif usage.percent >= 85:
                sev = Severity.WARN
            res.add(
                f"Disk {part.mountpoint}",
                sev,
                f"{usage.used // (1024**3)} / {usage.total // (1024**3)} GiB ({usage.percent:.1f}%) • {part.fstype}",
            )

        return res
