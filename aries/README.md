# ARIES — System Auditing Terminal

## Install

```bash
cd aries          # project root (the folder that contains aries.py and the aries/ package)
pip install -r requirements.txt
# optional (recommended):
pip install -e .
```

## Run (pick one)

**From the project root** (folder with `aries.py`, `audits/`, `requirements.txt`):

```bash
python aries.py
# or
PYTHONPATH=. python -m aries
# or
./run.sh
```

**After `pip install -e .`:**

```bash
aries
```

### Wrong location

```text
~/aries/aries   ← inside the package — DO NOT run here
python -m aries  → "No module named aries"
```

Go up one directory first:

```bash
cd ..
python aries.py
```

## Commands

`full` `quick` `security` `hardening` `logs` `files` `malware` `rootkit` `lynis` `fim` `export` `help` `quit`

Or type a path: `/etc/passwd`

Optional tools (prompted on start if missing):

```bash
sudo pacman -S lynis chkrootkit rkhunter clamav
sudo freshclam
```
