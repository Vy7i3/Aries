"""Systemd services audit."""

from __future__ import annotations

from .base import SectionResult, Severity, run_cmd

try:
    from aries.platform import is_linux, is_windows, is_macos, detect_os
except Exception:
    def is_linux():
        return True
    def is_windows():
        return False
    def is_macos():
        return False
    def detect_os():
        return "linux"


class Services:
    name = "Services"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)
        res.raw["platform"] = detect_os()

        if is_windows():
            code, out, _ = run_cmd(["sc", "query", "state=", "all"])
            if code != 0:
                code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 20 Name,Status | Out-String"])
            if code == 0 and out:
                res.add("Services", Severity.INFO, "enumerated via sc/powershell")
                res.raw["sample"] = out[:800]
            else:
                res.add("Services", Severity.SKIP, "cannot enumerate Windows services")
            return res

        if is_macos():
            code, out, _ = run_cmd(["launchctl", "list"])
            if code == 0 and out:
                lines = [L for L in out.splitlines() if L.strip()]
                res.add("launchctl jobs", Severity.INFO, f"{len(lines)} entries listed")
            else:
                res.add("launchctl", Severity.SKIP, "unavailable")
            return res

        # Linux systemd
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
