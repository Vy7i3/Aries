"""Security-related checks (SSH, firewall, SUID, ports…)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .base import SectionResult, Severity, run_cmd, file_exists, read_file


class Security:
    name = "Security"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)

        self._check_ssh(res)
        self._check_firewall(res)
        self._check_fail2ban(res)
        self._check_suid(res)
        self._check_listening_ports(res)
        self._check_kernel_hardening(res)
        self._check_umask(res)
        self._check_issue(res)
        self._check_motd(res)
        return res

    def _check_ssh(self, res: SectionResult) -> None:
        conf = "/etc/ssh/sshd_config"
        if not file_exists(conf):
            res.add("SSH", Severity.SKIP, "sshd_config not found")
            return

        content = read_file(conf) or ""
        # strip comments
        lines = [
            ln.strip()
            for ln in content.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        cfg = {}
        for ln in lines:
            parts = ln.split(None, 1)
            if len(parts) == 2:
                cfg[parts[0].lower()] = parts[1]

        # PermitRootLogin
        root_login = cfg.get("permitrootlogin", "yes").lower()
        if root_login in ("no", "prohibit-password", "without-password"):
            res.add("SSH PermitRootLogin", Severity.OK, root_login)
        else:
            res.add(
                "SSH PermitRootLogin",
                Severity.WARN,
                root_login,
                recommendation="Set PermitRootLogin no (or prohibit-password)",
            )

        # PasswordAuthentication
        pwd = cfg.get("passwordauthentication", "yes").lower()
        if pwd == "no":
            res.add("SSH PasswordAuthentication", Severity.OK, "disabled")
        else:
            res.add(
                "SSH PasswordAuthentication",
                Severity.WARN,
                "enabled",
                recommendation="Prefer key-based auth: PasswordAuthentication no",
            )

        # Port
        port = cfg.get("port", "22")
        if port != "22":
            res.add("SSH Port", Severity.OK, f"non-default ({port})")
        else:
            res.add("SSH Port", Severity.INFO, "22 (default)")

    def _check_firewall(self, res: SectionResult) -> None:
        # nftables
        code, out, _ = run_cmd(["nft", "list", "ruleset"])
        if code == 0 and out:
            res.add("Firewall (nftables)", Severity.OK, "rules present")
            res.raw["firewall"] = "nftables"
            return

        # iptables
        code, out, _ = run_cmd(["iptables", "-L", "-n"])
        if code == 0 and "Chain" in out:
            # very rough: any ACCEPT policy with rules?
            if "ACCEPT" in out or "DROP" in out or "REJECT" in out:
                res.add("Firewall (iptables)", Severity.OK, "rules present")
                res.raw["firewall"] = "iptables"
                return

        # ufw
        code, out, _ = run_cmd(["ufw", "status"])
        if code == 0:
            if "active" in out.lower():
                res.add("Firewall (ufw)", Severity.OK, "active")
                res.raw["firewall"] = "ufw"
                return
            else:
                res.add("Firewall (ufw)", Severity.WARN, "inactive")
                return

        # firewalld
        code, out, _ = run_cmd(["firewall-cmd", "--state"])
        if code == 0 and "running" in out.lower():
            res.add("Firewall (firewalld)", Severity.OK, "running")
            res.raw["firewall"] = "firewalld"
            return

        res.add(
            "Firewall",
            Severity.WARN,
            "no active firewall detected",
            recommendation="Enable nftables or ufw",
        )

    def _check_fail2ban(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(["systemctl", "is-active", "fail2ban"])
        if code == 0 and out == "active":
            res.add("Fail2ban", Severity.OK, "active")
        else:
            # also check if unit exists
            code2, _, _ = run_cmd(["systemctl", "status", "fail2ban"])
            if code2 == 0 or code2 == 3:
                res.add("Fail2ban", Severity.WARN, "installed but not active")
            else:
                res.add(
                    "Fail2ban",
                    Severity.INFO,
                    "not installed",
                    recommendation="Consider installing fail2ban for SSH brute-force protection",
                )

    def _check_suid(self, res: SectionResult) -> None:
        # Actually scan common binary directories (and one level of subdirs)
        paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]
        suid_files: list[str] = []
        for base in paths:
            if not os.path.isdir(base):
                continue
            try:
                for root, dirs, files in os.walk(base, followlinks=False):
                    # only one level deep under these
                    if root != base:
                        dirs.clear()
                    for name in files:
                        path = os.path.join(root, name)
                        try:
                            mode = os.lstat(path).st_mode
                        except OSError:
                            continue
                        if mode & 0o4000:  # SUID
                            suid_files.append(path)
            except PermissionError:
                continue

        count = len(suid_files)
        interesting = [f for f in suid_files if any(x in f for x in ("sudo", "su", "passwd", "mount", "pkexec"))]
        detail = f"{count} SUID binaries scanned"
        if interesting:
            detail += " • e.g. " + ", ".join(os.path.basename(f) for f in interesting[:5])
        res.add("SUID binaries", Severity.INFO, detail)
        res.raw["suid_count"] = count
        res.raw["suid_files"] = suid_files[:40]

    def _check_listening_ports(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(["ss", "-tuln"])
        if code != 0:
            code, out, _ = run_cmd(["netstat", "-tuln"])
        if code != 0 or not out:
            res.add("Listening ports", Severity.SKIP, "ss/netstat unavailable")
            return

        ports = set()
        for line in out.splitlines():
            # look for :PORT
            m = re.search(r":(\d+)\s", line)
            if m:
                ports.add(int(m.group(1)))

        common_risky = {21, 23, 25, 110, 143, 445, 3389}
        found_risky = sorted(ports & common_risky)
        detail = f"{len(ports)} listening ports"
        if found_risky:
            res.add(
                "Listening ports",
                Severity.WARN,
                f"{detail} • potentially risky: {found_risky}",
                recommendation="Review services bound to those ports",
            )
        else:
            res.add("Listening ports", Severity.OK, detail)
        res.raw["ports"] = sorted(ports)

    def _check_kernel_hardening(self, res: SectionResult) -> None:
        # Simple sysctl checks
        checks = {
            "kernel.randomize_va_space": ("2", "ASLR"),
            "net.ipv4.conf.all.rp_filter": ("1", "rp_filter"),
            "net.ipv4.tcp_syncookies": ("1", "SYN cookies"),
        }
        for key, (expected, label) in checks.items():
            path = f"/proc/sys/{key.replace('.', '/')}"
            val = read_file(path)
            if val is None:
                continue
            val = val.strip()
            if val == expected:
                res.add(f"Sysctl {label}", Severity.OK, f"{key}={val}")
            else:
                res.add(
                    f"Sysctl {label}",
                    Severity.WARN,
                    f"{key}={val} (expected {expected})",
                )

    def _check_umask(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(["bash", "-lc", "umask"])
        if code == 0 and out.strip():
            u = out.strip()
            if u in ("0022", "022", "0027", "027", "0077", "077"):
                sev = Severity.OK if u in ("0027", "027", "0077", "077") else Severity.INFO
                res.add("umask", sev, u)
            else:
                res.add("umask", Severity.WARN, u, "prefer 027 or 077")
        else:
            res.add("umask", Severity.SKIP, "n/a")

    def _check_issue(self, res: SectionResult) -> None:
        for name in ("/etc/issue", "/etc/issue.net"):
            p = Path(name)
            if p.is_file():
                try:
                    text = p.read_text(errors="replace")[:200]
                    if any(x in text for x in ("\\r", "\\v", "Welcome")):
                        res.add(name, Severity.INFO, "banner present")
                    else:
                        res.add(name, Severity.INFO, "present")
                except OSError:
                    pass

    def _check_motd(self, res: SectionResult) -> None:
        p = Path("/etc/motd")
        if p.is_file():
            res.add("/etc/motd", Severity.INFO, "present")
        else:
            res.add("/etc/motd", Severity.INFO, "absent")

