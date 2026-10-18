#!/usr/bin/env python3
"""Run ARIES from the project root:  python aries.py"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on sys.path (this file lives there)
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aries.__main__ import main

if __name__ == "__main__":
    main()
