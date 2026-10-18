# ARIES — System Auditing Terminal

**ARIES** is a beautiful, read-only and interactive system auditing tool for Arch Linux (and Arch-based distros).  
Inspired by the clean Hermes-style terminal interface with a white/grey/dark-grey gradient title and a goat-with-horns pixel art.

```
     █████╗ ██████╗ ██╗███████╗███████╗
    ██╔══██╗██╔══██╗██║██╔════╝██╔════╝
    ███████║██████╔╝██║█████╗  ███████╗
    ██╔══██║██╔══██╗██║██╔══╝  ╚════██║
    ██║  ██║██║  ██║██║███████╗███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
```

## Features

- **System overview** — hostname, kernel, uptime, Arch version
- **Resources** — CPU, RAM, disk, load
- **Security** — SSH config, firewall (nftables/iptables/ufw), fail2ban, SUID binaries, open ports
- **Packages** — outdated packages, optional `arch-audit` vulnerability check
- **Services** — failed/running systemd units
- **Users & privileges** — UID 0 accounts, sudoers highlights
- Clean gradient banner + pixel goat art
- JSON export support
- Fully read-only (never modifies the system)

## Requirements

- Arch Linux / EndeavourOS / CachyOS / Manjaro (or any systemd Linux)
- Python ≥ 3.10
- Optional: `arch-audit` (from official repos or AUR) for package vulnerability scanning

```bash
sudo pacman -S python python-pip python-psutil
# optional
sudo pacman -S arch-audit
```

## Install & Run

```bash
cd aries
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run (some checks need root for full visibility)
python -m aries
# or
sudo python -m aries
```

### One-liner (after cloning)

```bash
pip install -r requirements.txt && python -m aries
```

## Usage

```
aries                  # interactive full audit
aries --quick          # fast overview only
aries --json           # machine-readable output
aries --section security
aries --help
```

## License

MIT — free to use, modify, and share.

## Caution

This Version Is still UNDER DEVELOPMENT, USE WITH YOUR CAUTION, there may be bugs and false positives.
