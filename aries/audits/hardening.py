"""
System hardening checks (original Python).

Uses aries/repo/systemd_hardening.json for optimal values and recommendations
on systemd-based Linux.
"""

from __future__ import annotations

import os
from pathlib import Path

from .base import SectionResult, Severity, run_cmd

try:
    from aries.knowledge import (
        load_systemd_hardening,
        sysctl_recommendation,
        mount_recommendation,
        unit_hardening_tips,
        critical_permission_files,
    )
except Exception:
    load_systemd_hardening = None
    sysctl_recommendation = None
    mount_recommendation = None
    unit_hardening_tips = None
    critical_permission_files = None


def _read_sysctl(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def _sysctl_path(key: str) -> str:
    # kernel.randomize_va_space -> /proc/sys/kernel/randomize_va_space
    return "/proc/sys/" + key.replace(".", "/")


class Hardening:
    name = "Hardening"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)
        self._sysctl_from_repo(res)
        self._auth(res)
        self._network_extra(res)
        self._logging(res)
        self._permissions(res)
        self._filesystem_mounts(res)
        self._core_dumps(res)
        self._compiler_presence(res)
        self._systemd_system_conf(res)
        self._systemd_unit_tips(res)
        return res

    def _sysctl_from_repo(self, res: SectionResult) -> None:
        """Compare live sysctl values to optimal settings in the knowledge repo."""
        data = {}
        if load_systemd_hardening:
            data = (load_systemd_hardening() or {}).get("sysctl") or {}

        # Fallback minimal set if repo missing
        if not data:
            data = {
                "kernel.randomize_va_space": {"optimal": "2"},
                "kernel.dmesg_restrict": {"optimal": "1"},
                "kernel.kptr_restrict": {"optimal": "2"},
                "net.ipv4.tcp_syncookies": {"optimal": "1"},
                "net.ipv4.ip_forward": {"optimal": "0"},
            }

        for key, meta in data.items():
            optimal = str(meta.get("optimal", ""))
            path = _sysctl_path(key)
            got = _read_sysctl(path)
            label = key
            if got is None:
                res.add(label, Severity.SKIP, "not available on this kernel")
                continue
            # Accept some equivalents (e.g. kptr 1 or 2)
            ok_values = {optimal}
            if key == "kernel.kptr_restrict":
                ok_values = {"1", "2"}
            if key == "kernel.unprivileged_bpf_disabled":
                ok_values = {"1", "2"}
            if key == "kernel.yama.ptrace_scope":
                ok_values = {"1", "2", "3"}

            rec = None
            if sysctl_recommendation:
                rec = sysctl_recommendation(key)

            if got in ok_values:
                res.add(label, Severity.OK, f"{got} (optimal)")
            else:
                res.add(
                    label,
                    Severity.WARN,
                    f"{got} (want {optimal})",
                    recommendation=rec or f"set {key}={optimal}",
                )

    def _auth(self, res: SectionResult) -> None:
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
                    elif n in (99999, -1):
                        res.add(
                            "PASS_MAX_DAYS",
                            Severity.WARN,
                            str(n),
                            recommendation="Set a finite password max age (e.g. 90)",
                        )
                    else:
                        res.add("PASS_MAX_DAYS", Severity.INFO, str(n))
            except OSError:
                pass

        pam_dir = Path("/etc/pam.d")
        if pam_dir.is_dir():
            has_faillock = False
            try:
                for f in pam_dir.iterdir():
                    if f.is_file() and (
                        "faillock" in f.read_text(errors="replace")
                        or "tally2" in f.read_text(errors="replace")
                    ):
                        has_faillock = True
                        break
            except OSError:
                pass
            if has_faillock:
                res.add("PAM lockout", Severity.OK, "faillock/tally referenced")
            else:
                res.add(
                    "PAM lockout",
                    Severity.INFO,
                    "no faillock/tally seen",
                    recommendation="Consider pam_faillock for brute-force lockout",
                )

    def _network_extra(self, res: SectionResult) -> None:
        code, out, _ = run_cmd(["ss", "-tulpn"])
        if code == 0 and out:
            lines = [L for L in out.splitlines() if L.strip() and not L.startswith("Netid")]
            res.add("Listening sockets", Severity.INFO, f"{len(lines)} entries (ss -tulpn)")
            res.raw["ss_sample"] = lines[:30]
        else:
            res.add("Listening sockets", Severity.SKIP, "ss unavailable")

    def _logging(self, res: SectionResult) -> None:
        journal = Path("/var/log/journal")
        if journal.is_dir() or Path("/var/log/messages").is_file() or Path("/var/log/syslog").is_file():
            res.add("System logs", Severity.OK, "journal and/or syslog present")
        else:
            res.add("System logs", Severity.WARN, "no common log paths found")

        code, out, _ = run_cmd(["systemctl", "is-active", "auditd"])
        if code == 0 and (out or "").strip() == "active":
            res.add("auditd", Severity.OK, "active")
        elif Path("/etc/audit").is_dir():
            res.add(
                "auditd",
                Severity.WARN,
                "installed but not active",
                recommendation="systemctl enable --now auditd",
            )
        else:
            res.add(
                "auditd",
                Severity.INFO,
                "not installed",
                recommendation="Consider auditd for security-relevant audit trails",
            )

    def _permissions(self, res: SectionResult) -> None:
        files = {}
        if critical_permission_files:
            files = critical_permission_files() or {}
        if not files:
            files = {
                "/etc/passwd": {"world_write": False},
                "/etc/shadow": {"world_read": False},
                "/etc/ssh/sshd_config": {"world_write": False},
            }

        for path, rules in files.items():
            p = Path(path)
            if not p.exists():
                continue
            try:
                mode = p.stat().st_mode & 0o777
                if rules.get("world_read") is False and mode & 0o004:
                    res.add(path, Severity.CRITICAL, f"mode {oct(mode)} world-readable")
                elif rules.get("world_write") is False and mode & 0o002:
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
            _dev, mnt, _fstype, opts = parts[0], parts[1], parts[2], parts[3]
            if mnt in ("/tmp", "/dev/shm", "/var/tmp"):
                if "noexec" not in opts or "nosuid" not in opts:
                    rec = mount_recommendation(mnt) if mount_recommendation else None
                    issues.append((mnt, opts, rec))
        if issues:
            for mnt, opts, rec in issues[:5]:
                res.add(
                    f"Mount {mnt}",
                    Severity.WARN,
                    f"options={opts}",
                    recommendation=rec or "add noexec,nosuid,nodev",
                )
        else:
            res.add("Mount hardening", Severity.OK, "tmp/shm flags look fine or n/a")

    def _core_dumps(self, res: SectionResult) -> None:
        v = _read_sysctl("/proc/sys/fs/suid_dumpable")
        if v is None:
            res.add("suid_dumpable", Severity.SKIP, "n/a")
        elif v == "0":
            res.add("suid_dumpable", Severity.OK, "0")
        else:
            rec = sysctl_recommendation("fs.suid_dumpable") if sysctl_recommendation else None
            res.add("suid_dumpable", Severity.WARN, v, recommendation=rec)

    def _compiler_presence(self, res: SectionResult) -> None:
        import shutil

        found = [c for c in ("gcc", "g++", "cc", "clang") if shutil.which(c)]
        if found:
            res.add(
                "Compilers present",
                Severity.INFO,
                ", ".join(found),
                recommendation="On production servers, consider removing toolchains",
            )
        else:
            res.add("Compilers present", Severity.OK, "none of gcc/clang in PATH")

    def _systemd_system_conf(self, res: SectionResult) -> None:
        conf = Path("/etc/systemd/system.conf")
        if not conf.is_file():
            res.add("systemd system.conf", Severity.SKIP, "not found")
            return
        try:
            text = conf.read_text(errors="replace")
        except OSError:
            res.add("systemd system.conf", Severity.SKIP, "unreadable")
            return

        data = {}
        if load_systemd_hardening:
            data = (load_systemd_hardening() or {}).get("systemd_system") or {}

        checks = data or {
            "DumpCore": {"optimal": "no"},
            "CtrlAltDelBurstAction": {"optimal": "none"},
        }

        active = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            active[k.strip()] = v.strip()

        for key, meta in checks.items():
            want = str(meta.get("optimal", ""))
            got = active.get(key)
            if got is None:
                res.add(
                    f"systemd {key}",
                    Severity.INFO,
                    "not set (using default)",
                    recommendation=f"Consider {key}={want} in /etc/systemd/system.conf — {meta.get('why', '')}",
                )
            elif got.lower() == want.lower():
                res.add(f"systemd {key}", Severity.OK, got)
            else:
                res.add(
                    f"systemd {key}",
                    Severity.WARN,
                    f"{got} (want {want})",
                    recommendation=f"Set {key}={want} — {meta.get('why', '')}",
                )

    def _systemd_unit_tips(self, res: SectionResult) -> None:
        """Surface unit hardening best practices as informational recommendations."""
        tips = unit_hardening_tips() if unit_hardening_tips else []
        if not tips:
            res.add(
                "Unit hardening",
                Severity.INFO,
                "Prefer NoNewPrivileges, ProtectSystem=strict, PrivateTmp for services",
            )
            return
        # Summarize top tips as one finding + store all in raw
        res.add(
            "systemd unit sandboxing",
            Severity.INFO,
            f"{len(tips)} recommended directives for services",
            recommendation="; ".join(tips[:4]) + ("…" if len(tips) > 4 else ""),
        )
        res.raw["unit_hardening_tips"] = tips
