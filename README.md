# ARIES

ARIES is a local system auditing terminal for Arch Linux. Run it from the project root with `python aries.py` (or `pip install -e .` then `aries`), type commands like `full`, `quick`, `security`, `hardening`, `logs`, `files`, `fim`, `malware`, `rootkit`, or `lynis` at the prompt, optionally install Lynis/chkrootkit/rkhunter/ClamAV when asked, and export results to JSON. Requires Python 3.10+, rich, psutil, and click.
