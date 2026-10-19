# ARIES

```
     /\  \         /\  \          ___        /\  \         /\  \    
    /::\  \       /::\  \        /\  \      /::\  \       /::\  \   
   /:/\:\  \     /:/\:\  \       \:\  \    /:/\:\  \     /:/\ \  \  
  /::\~\:\  \   /::\~\:\  \      /::\__\  /::\~\:\  \   _\:\~\ \  \ 
 /:/\:\ \:\__\ /:/\:\ \:\__\  __/:/\/__/ /:/\:\ \:\__\ /\ \:\ \ \__\
 \/__\:\/:/  / \/_|::\/:/  / /\/:/  /    \:\~\:\ \/__/ \:\ \:\ \/__/
      \::/  /     |:|::/  /  \::/__/      \:\ \:\__\    \:\ \:\__\  
      /:/  /      |:|\/__/    \:\__\       \:\ \/__/     \:\/:/  /  
     /:/  /       |:|  |       \/__/        \:\__\        \::/  /   
     \/__/         \|__|                     \/__/         \/__/    
```

System auditing terminal for Arch Linux.

Interactive TUI with a chat-style prompt. Local-only — no cloud account required.

Layout:

```
title  — left, above the frame
goat   — boxed on the left
tools  — boxed on the right
chat   — type a command or a path
```

---

## Features

- Interactive dashboard (title, goat art, command list)
- Full audit suite: system, resources, security, hardening, users, packages, services
- Deep file scan with hashing and heuristics
- Integrity baseline (build / compare) under `~/.local/share/aries/`
- Rootkit indicators: paths, processes, modules, PROMISC interfaces
- Log audit: journal errors, failed logins, sudo, cron
- Optional tools: Lynis, chkrootkit, rkhunter, ClamAV (when installed)
- Safe elevation: asks before sudo; password via getpass, never stored

---

## Requirements

- Python 3.10+
- Dependencies: `rich`, `psutil`, `click`
- Linux (tuned for Arch Linux)

---

## Install

```bash
git clone <your-repo-url> aries
cd aries

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Editable install (adds `aries` to PATH):

```bash
pip install -e .
```

Optional packages (Arch):

```bash
sudo pacman -S lynis chkrootkit rkhunter clamav
sudo freshclam
```

On first launch, ARIES can prompt to install missing optional tools.

---

## Run

Always start from the **project root** (the folder that contains `aries.py`, `audits/`, and `requirements.txt`).

```bash
python aries.py
```

```bash
./run.sh
```

```bash
PYTHONPATH=. python -m aries
```

```bash
aries
```

(The last form works after `pip install -e .`.)

Wrong vs right directory:

```
wrong:  ~/aries/aries     (inside the package → No module named aries)
right:  ~/aries           (project root)
```

---

## Commands

Type at the `aries` prompt:

| Command     | Action                                      |
|-------------|---------------------------------------------|
| `full`      | Every module + deep file pass               |
| `quick`     | System, resources, services                 |
| `security`  | SSH, firewall, SUID, banners                |
| `hardening` | Kernel, sysctl, mounts, modes               |
| `logs`      | Journal, failures, sudo, cron               |
| `files`     | Deep per-file scan                          |
| `malware`   | ClamAV or heuristics                        |
| `rootkit`   | chkrootkit + rkhunter if present            |
| `lynis`     | Lynis audit if present                      |
| `fim`       | Integrity baseline build / check            |
| `export`    | Write last results as JSON                  |
| `/path`     | Scan a single file                          |
| `help`      | List commands                               |
| `quit`      | Exit                                        |

---

## Architecture

```
aries/
├── aries.py           # launcher
├── run.sh             # PYTHONPATH-safe entry
├── aries/             # TUI package
│   ├── __main__.py    # chat loop and dispatch
│   ├── dashboard.py   # layout
│   ├── banner.py      # wordmark and art
│   ├── scanner.py     # deep scan and FIM
│   ├── deps.py        # optional install prompts
│   └── exttools.py    # external binary wrappers
└── audits/            # check modules
    ├── system.py
    ├── security.py
    ├── hardening.py
    ├── rootkit.py
    ├── logs.py
    ├── filesystem.py
    └── ...
```

Severity levels: `ok`, `info`, `warn`, `critical`, `skip`.

---

## Example session

```text
aries › hardening
  ✓  ASLR                 full randomization (2)
  !  dmesg_restrict       disabled
  !  kptr_restrict        value=0
  ✓  tcp_syncookies       1

aries › files
  Scanning files… 100%
  files=2341  hashed=2104  denied=12  time=4.2s

aries › export
  Save JSON to (aries-report.json):
  Saved → aries-report.json
```

---

## License

MIT
