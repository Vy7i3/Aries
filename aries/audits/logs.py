"""Log and audit-trail checks (original)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .base import SectionResult, Severity, run_cmd


class LogAudit:
    name = "Logs"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)
        self._journal(res)
        self._auth_log(res)
        self._failed_logins(res)
        self._sudo_log(res)
        self._cron_log(res)
        return res

    def _journal(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(["journalctl", "-b", "-p", "err", "-n", "20", "--no-pager"])
        if code != 0:
            res.add("Journal errors", Severity.SKIP, "journalctl unavailable")
            return
        lines = [L for L in (out or "").splitlines() if L.strip()]
        if not lines:
            res.add("Journal errors (boot)", Severity.OK, "no err-level entries in sample")
        else:
            res.add(
                "Journal errors (boot)",
                Severity.WARN if len(lines) > 5 else Severity.INFO,
                f"{len(lines)} recent err lines",
            )
            res.raw["journal_err_sample"] = lines[:10]

    def _auth_log(self, res: SectionResult) -> None:
        candidates = [
            Path("/var/log/auth.log"),
            Path("/var/log/secure"),
            Path("/var/log/messages"),
        ]
        found = next((p for p in candidates if p.is_file()), None)
        if not found:
            # try journal for ssh
            code, out, _ = run_cmd(
                ["journalctl", "-u", "sshd", "-n", "5", "--no-pager"]
            )
            if code == 0 and out.strip():
                res.add("Auth source", Severity.OK, "sshd via journald")
            else:
                res.add("Auth log file", Severity.INFO, "no classic auth.log/secure found")
            return
        try:
            size = found.stat().st_size
            res.add("Auth log file", Severity.OK, f"{found} ({size} bytes)")
        except OSError:
            res.add("Auth log file", Severity.SKIP, str(found))

    def _failed_logins(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(
            ["journalctl", "-b", "-g", "Failed password|authentication failure", "-n", "50", "--no-pager"]
        )
        if code != 0:
            res.add("Failed logins", Severity.SKIP, "cannot query journal")
            return
        lines = [L for L in (out or "").splitlines() if L.strip()]
        n = len(lines)
        if n == 0:
            res.add("Failed logins (boot)", Severity.OK, "none in journal sample")
        elif n < 10:
            res.add("Failed logins (boot)", Severity.INFO, f"{n} events")
        else:
            res.add(
                "Failed logins (boot)",
                Severity.WARN,
                f"{n}+ events — possible brute force",
                "Review sshd / fail2ban",
            )
            res.raw["failed_login_sample"] = lines[:8]

    def _sudo_log(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(
            ["journalctl", "-b", "-g", "sudo:", "-n", "15", "--no-pager"]
        )
        if code != 0:
            res.add("sudo activity", Severity.SKIP, "n/a")
            return
        lines = [L for L in (out or "").splitlines() if L.strip()]
        res.add("sudo activity (boot)", Severity.INFO, f"{len(lines)} journal hits")

    def _cron_log(self, res: SectionResult) -> None:
        paths = list(Path("/etc/cron.d").glob("*")) if Path("/etc/cron.d").is_dir() else []
        user_cron = Path("/var/spool/cron")
        extra = 0
        if user_cron.is_dir():
            try:
                extra = len(list(user_cron.iterdir()))
            except OSError:
                pass
        res.add(
            "Cron config",
            Severity.INFO,
            f"{len(paths)} files in cron.d, {extra} user spool entries",
        )
