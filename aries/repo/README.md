# ARIES knowledge repository (per OS)

```
repo/
  linux/
    dangerous_indicators.json
    hardening.json          # sysctl + systemd + sshd + mounts
  windows/
    dangerous_indicators.json
    hardening.json
  macos/
    dangerous_indicators.json
    hardening.json
```

ARIES detects the host OS and loads the matching folder automatically.
