"""Systemd services audit."""

from __future__ import annotations

from .base import SectionResult, Severity, run_cmd


class Services:
    name = "Services"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)

        # Failed units
        code, out, _ = run_cmd(["systemctl", "--failed", "--no-legend", "--no-pager"])
        if code == 0:
            failed = [ln.strip() for ln in out.splitlines() if ln.strip()]
            if failed:
                res.add(
                    "Failed units",
                    Severity.CRITICAL if len(failed) > 3 else Severity.WARN,
                    f"{len(failed)} failed • " + ", ".join(f.split()[0] for f in failed[:5]),
                    recommendation="Inspect with: systemctl --failed",
                )
                res.raw["failed"] = failed
            else:
                res.add("Failed units", Severity.OK, "none")
        else:
            res.add("Failed units", Severity.SKIP, "systemctl unavailable")

        # Running units count
        code, out, _ = run_cmd(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"]
        )
        if code == 0:
            running = [ln for ln in out.splitlines() if ln.strip()]
            res.add("Running services", Severity.INFO, f"{len(running)} services")
            res.raw["running_count"] = len(running)

        # Important security-related services
        important = {
            "sshd": "SSH daemon",
            "firewalld": "Firewall",
            "nftables": "nftables",
            "fail2ban": "Fail2ban",
            "auditd": "Linux Audit",
            "chronyd": "Time sync",
            "systemd-timesyncd": "Time sync",
        }
        for unit, label in important.items():
            code, out, _ = run_cmd(["systemctl", "is-active", unit])
            if out == "active":
                res.add(f"Service {label}", Severity.OK, "active")
            elif out in ("inactive", "dead"):
                # only warn for ones that are usually expected
                if unit in ("sshd", "fail2ban", "auditd"):
                    res.add(f"Service {label}", Severity.INFO, out or "inactive")
            # else skip silently if unit doesn't exist

        return res
