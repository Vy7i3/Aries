# ARIES knowledge repository

| File | Purpose |
|------|---------|
| `dangerous_indicators.json` | Paths, process names, modules, permission risks, auth/network red flags |
| `systemd_hardening.json` | Optimal sysctl, systemd system.conf, unit sandboxing, sshd, mount options |

Loaded at runtime by `aries.knowledge`. Edit these files to extend what ARIES looks for and recommends during `hardening`.
