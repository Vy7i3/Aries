"""
System hardening checks (original Python).

Check categories aligned with common audit practice (kernel, auth, network,
logging, permissions) — same problem space as tools like Lynis, implemented
from scratch for ARIES / Arch Linux.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .base import SectionResult, Severity, run_cmd


class Hardening:
    name = "Hardening"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)
        self._kernel(res)
        self._sysctl(res)
        self._auth(res)
        self._network(res)
        self._logging(res)
        self._permissions(res)
        self._filesystem_mounts(res)
        self._core_dumps(res)
        self._compiler_presence(res)
        return res

    def _kernel(self, res: SectionResult) -> None:
        # ASLR
        try:
            aslr = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
            if aslr == "2":
                res.add("ASLR", Severity.OK, "full randomization (2)")
            elif aslr == "1":
                res.add("ASLR", Severity.WARN, "partial (1)", "set kernel.randomize_va_space=2")
            else:
                res.add("ASLR", Severity.CRITICAL, f"value={aslr}", "enable ASLR")
        except OSError:
            res.add("ASLR", Severity.SKIP, "cannot read")

        # dmesg restrict
        try:
            v = Path("/proc/sys/kernel/dmesg_restrict").read_text().strip()
            if v == "1":
                res.add("dmesg_restrict", Severity.OK, "enabled")
            else:
                res.add("dmesg_restrict", Severity.WARN, "disabled", "kernel.dmesg_restrict=1")
        except OSError:
            res.add("dmesg_restrict", Severity.SKIP, "cannot read")

        # kptr_restrict
        try:
            v = Path("/proc/sys/kernel/kptr_restrict").read_text().strip()
            if v in ("1", "2"):
                res.add("kptr_restrict", Severity.OK, f"value={v}")
            else:
                res.add("kptr_restrict", Severity.WARN, f"value={v}", "kernel.kptr_restrict=1 or 2")
        except OSError:
            res.add("kptr_restrict", Severity.SKIP, "cannot read")

        # unprivileged bpf
        p = Path("/proc/sys/kernel/unprivileged_bpf_disabled")
        if p.is_file():
            try:
                v = p.read_text().strip()
                if v in ("1", "2"):
                    res.add("unprivileged_bpf", Severity.OK, f"disabled ({v})")
                else:
                    res.add("unprivileged_bpf", Severity.WARN, "allowed", "kernel.unprivileged_bpf_disabled=1")
            except OSError:
                pass

    def _sysctl(self, res: SectionResult) -> None:
        checks = {
            "/proc/sys/net/ipv4/conf/all/rp_filter": ("1", "rp_filter"),
            "/proc/sys/net/ipv4/conf/all/accept_redirects": ("0", "accept_redirects"),
            "/proc/sys/net/ipv4/conf/all/send_redirects": ("0", "send_redirects"),
            "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts": ("1", "ignore_broadcasts"),
            "/proc/sys/net/ipv4/tcp_syncookies": ("1", "tcp_syncookies"),
        }
        for path, (want, label) in checks.items():
            try:
                got = Path(path).read_text().strip()
                if got == want:
                    res.add(label, Severity.OK, f"{got}")
                else:
                    res.add(label, Severity.WARN, f"{got} (want {want})")
            except OSError:
                res.add(label, Severity.SKIP, "n/a")

    def _auth(self, res: SectionResult) -> None:
        # login.defs PASS_MAX_DAYS
        login_defs = Path("/etc/login.defs")
        if login_defs.is_file():
            try:
                text = login_defs.read_text(errors="replace")
                max_days = None
                for line in text.splitlines():
                    if line.strip().startswith("PASS_MAX_DAYS"):
                        parts = line.split()
                        if len(parts) >= 2:
                            max_days = parts[1]
                if max_days and max_days.isdigit():
                    n = int(max_days)
                    if 0 < n <= 90:
                        res.add("PASS_MAX_DAYS", Severity.OK, str(n))
                    elif n == 99999 or n == -1:
                        res.add("PASS_MAX_DAYS", Severity.WARN, str(n), "set a finite password max age")
                    else:
                        res.add("PASS_MAX_DAYS", Severity.INFO, str(n))
            except OSError:
                pass

        # pam faillock / tally
        pam_dir = Path("/etc/pam.d")
        if pam_dir.is_dir():
            has_faillock = False
            try:
                for f in pam_dir.iterdir():
                    if f.is_file():
                        body = f.read_text(errors="replace")
                        if "faillock" in body or "tally2" in body:
                            has_faillock = True
                            break
            except OSError:
                pass
            if has_faillock:
                res.add("PAM lockout", Severity.OK, "faillock/tally referenced")
            else:
                res.add("PAM lockout", Severity.INFO, "no faillock/tally seen in /etc/pam.d")

    def _network(self, res: SectionResult) -> None:
        # IP forwarding
        try:
            v = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
            if v == "0":
                res.add("IPv4 forwarding", Severity.OK, "disabled")
            else:
                res.add("IPv4 forwarding", Severity.WARN, "enabled", "disable unless this is a router")
        except OSError:
            res.add("IPv4 forwarding", Severity.SKIP, "n/a")

        # Listening sockets summary
        code, out, _ = run_cmd(["ss", "-tulpn"])
        if code == 0 and out:
            lines = [L for L in out.splitlines() if L.strip() and not L.startswith("Netid")]
            res.add("Listening sockets", Severity.INFO, f"{len(lines)} entries (ss -tulpn)")
            res.raw["ss_sample"] = lines[:30]
        else:
            res.add("Listening sockets", Severity.SKIP, "ss unavailable")

    def _logging(self, res: SectionResult) -> None:
        journal = Path("/var/log/journal")
        messages = Path("/var/log/messages")
        syslog = Path("/var/log/syslog")
        if journal.is_dir() or messages.is_file() or syslog.is_file():
            res.add("System logs", Severity.OK, "journal and/or syslog present")
        else:
            res.add("System logs", Severity.WARN, "no common log paths found")

        # auditd
        code, out, _ = run_cmd(["systemctl", "is-active", "auditd"])
        if code == 0 and out.strip() == "active":
            res.add("auditd", Severity.OK, "active")
        elif shutil_which("auditd") or Path("/etc/audit").is_dir():
            res.add("auditd", Severity.WARN, "installed but not active")
        else:
            res.add("auditd", Severity.INFO, "not installed")

    def _permissions(self, res: SectionResult) -> None:
        critical = {
            "/etc/passwd": 0o644,
            "/etc/shadow": 0o640,  # often 000/640/600
            "/etc/gshadow": 0o640,
            "/etc/group": 0o644,
            "/etc/ssh/sshd_config": 0o600,
        }
        for path, max_mode in critical.items():
            p = Path(path)
            if not p.exists():
                continue
            try:
                mode = p.stat().st_mode & 0o777
                # shadow/gshadow: any world-readable is bad
                if path.endswith("shadow") or path.endswith("gshadow"):
                    if mode & 0o004:
                        res.add(path, Severity.CRITICAL, f"mode {oct(mode)} world-readable")
                    elif mode & 0o044:
                        res.add(path, Severity.WARN, f"mode {oct(mode)}")
                    else:
                        res.add(path, Severity.OK, f"mode {oct(mode)}")
                else:
                    if mode & 0o002:
                        res.add(path, Severity.WARN, f"mode {oct(mode)} world-writable")
                    else:
                        res.add(path, Severity.OK, f"mode {oct(mode)}")
            except OSError:
                res.add(path, Severity.SKIP, "unreadable")


    def _filesystem_mounts(self, res: SectionResult) -> None:
        try:
            mounts = Path("/proc/mounts").read_text().splitlines()
        except OSError:
            res.add("Mount options", Severity.SKIP, "cannot read /proc/mounts")
            return
        issues = []
        for line in mounts:
            parts = line.split()
            if len(parts) < 4:
                continue
            device, mnt, fstype, opts = parts[0], parts[1], parts[2], parts[3]
            if mnt == "/tmp" and "noexec" not in opts:
                issues.append("/tmp without noexec")
            if mnt == "/dev/shm" and "nosuid" not in opts:
                issues.append("/dev/shm without nosuid")
            if mnt == "/home" and "nodev" not in opts and fstype not in ("autofs", "nfs"):
                pass  # optional, skip noise
        if issues:
            res.add("Mount hardening", Severity.WARN, "; ".join(issues[:5]))
        else:
            res.add("Mount hardening", Severity.OK, "common tmp/shm flags look fine or n/a")

    def _core_dumps(self, res: SectionResult) -> None:
        # limits + sysctl
        try:
            v = Path("/proc/sys/fs/suid_dumpable").read_text().strip()
            if v == "0":
                res.add("suid_dumpable", Severity.OK, "0")
            else:
                res.add("suid_dumpable", Severity.WARN, v, "prefer fs.suid_dumpable=0")
        except OSError:
            res.add("suid_dumpable", Severity.SKIP, "n/a")

    def _compiler_presence(self, res: SectionResult) -> None:
        import shutil
        found = [c for c in ("gcc", "g++", "cc", "clang") if shutil.which(c)]
        if found:
            res.add(
                "Compilers present",
                Severity.INFO,
                ", ".join(found),
                "On production servers, consider removing toolchains",
            )
        else:
            res.add("Compilers present", Severity.OK, "none of gcc/clang in PATH")

def shutil_which(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None
