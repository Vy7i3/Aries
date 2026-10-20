"""Package & vulnerability checks (Arch-focused)."""

from __future__ import annotations

from .base import SectionResult, Severity, run_cmd

try:
    from aries.platform import detect_os, is_linux, is_windows, is_macos
except Exception:
    def detect_os():
        return "linux"
    def is_linux():
        return True
    def is_windows():
        return False
    def is_macos():
        return False


class Packages:
    name = "Packages"

    def run(self) -> SectionResult:
        res = SectionResult(name=self.name)
        res.raw["platform"] = detect_os()

        if is_windows():
            code, out, _ = run_cmd(["winget", "--version"])
            if code == 0:
                res.add("Package manager", Severity.INFO, f"winget available ({(out or '').strip()[:40]})")
            else:
                code2, out2, _ = run_cmd(["choco", "-v"])
                if code2 == 0:
                    res.add("Package manager", Severity.INFO, f"chocolatey {(out2 or '').strip()[:40]}")
                else:
                    res.add("Package manager", Severity.INFO, "use Windows Update / winget / choco")
            res.add("Updates", Severity.INFO, "Check Settings → Windows Update", recommendation="Install OS and driver updates regularly")
            return res

        if is_macos():
            code, out, _ = run_cmd(["brew", "--version"])
            if code == 0:
                res.add("Homebrew", Severity.INFO, (out or "").splitlines()[0][:60] if out else "present")
            else:
                res.add("Homebrew", Severity.INFO, "not found (optional)")
            code, out, _ = run_cmd(["softwareupdate", "-l"])
            if code == 0:
                res.add("softwareupdate", Severity.INFO, "queried available updates")
                res.raw["softwareupdate"] = (out or "")[:500]
            else:
                res.add("softwareupdate", Severity.SKIP, "cannot query")
            return res

        # Linux — prefer pacman, then dpkg/rpm
        code, out, _ = run_cmd(["pacman", "-Q"])
        if code == 0:
            pkgs = [ln for ln in out.splitlines() if ln.strip()]
            res.add("Installed packages", Severity.INFO, f"{len(pkgs)} packages")
            res.raw["package_count"] = len(pkgs)
        else:
            res.add("Installed packages", Severity.SKIP, "pacman not available")
            return res

        # Outdated packages
        code, out, err = run_cmd(["pacman", "-Qu"])
        if code == 0:
            outdated = [ln for ln in out.splitlines() if ln.strip()]
            if outdated:
                res.add(
                    "Outdated packages",
                    Severity.WARN,
                    f"{len(outdated)} package(s) can be upgraded",
                    recommendation="Run: sudo pacman -Syu",
                )
                res.raw["outdated"] = outdated[:20]  # sample
            else:
                res.add("Outdated packages", Severity.OK, "system is up to date")
        else:
            # pacman -Qu returns 1 when nothing to upgrade on some versions
            if "error" not in err.lower():
                res.add("Outdated packages", Severity.OK, "system is up to date")
            else:
                res.add("Outdated packages", Severity.SKIP, "could not check")

        # arch-audit (optional)
        code, out, _ = run_cmd(["arch-audit", "-u"])
        if code == 0 or (out and "vulnerable" in out.lower()):
            lines = [ln for ln in out.splitlines() if ln.strip()]
            if lines:
                res.add(
                    "arch-audit vulnerabilities",
                    Severity.WARN if lines else Severity.OK,
                    f"{len(lines)} issue(s) reported",
                    recommendation="Review: arch-audit",
                )
                res.raw["arch_audit"] = lines[:15]
            else:
                res.add("arch-audit", Severity.OK, "no known vulnerable packages")
        else:
            # try without -u
            code2, out2, _ = run_cmd(["arch-audit"])
            if code2 == 0 and out2.strip():
                lines = [ln for ln in out2.splitlines() if ln.strip()]
                sev = Severity.WARN if lines else Severity.OK
                res.add("arch-audit", sev, f"{len(lines)} finding(s)")
            else:
                res.add(
                    "arch-audit",
                    Severity.INFO,
                    "not installed",
                    recommendation="Install with: sudo pacman -S arch-audit",
                )

        # Orphan packages
        code, out, _ = run_cmd(["pacman", "-Qtdq"])
        if code == 0:
            orphans = [ln for ln in out.splitlines() if ln.strip()]
            if orphans:
                res.add(
                    "Orphan packages",
                    Severity.INFO,
                    f"{len(orphans)} orphan(s)",
                    recommendation="Review with: pacman -Qtdq",
                )
            else:
                res.add("Orphan packages", Severity.OK, "none")

        return res
