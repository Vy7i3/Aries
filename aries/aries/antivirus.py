"""
ARIES local antivirus engine (original implementation).

Technique: SHA-256 hash matching against local signature packs
(same general approach used by many lightweight open-source scanners).

This module is written from scratch for ARIES. Signature text files under
signatures/ are malware hash lists (one hash per line, optional trailing ';').
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from functools import lru_cache
from typing import Iterable

# Project root: .../aries/ (parent of package aries/)
_PKG_DIR = Path(__file__).resolve().parent
_ROOT = _PKG_DIR.parent
_SIG_DIR = _ROOT / "signatures"

MAX_HASH_BYTES = 100 * 1024 * 1024  # skip huge files for full hash

def is_self_path(path: str | Path) -> bool:
    """True if path is inside the ARIES project (avoid self false positives)."""
    try:
        p = Path(path).resolve()
        root = _ROOT.resolve()
        if root in p.parents or p == root:
            return True
        # signature text files are never "infected binaries"
        if p.suffix.lower() == ".txt" and "signature" in str(p).lower():
            return True
        if p.name.startswith("SHA256-Hashes"):
            return True
        parts = {x.lower() for x in p.parts}
        if "aries" in parts and ("signatures" in parts or "audits" in parts):
            # only skip if under a path segment that looks like this project
            if any(s in p.parts for s in ("signatures", "audits")):
                try:
                    if (_ROOT / "signatures").resolve() in p.parents or p.parent == (_ROOT / "signatures").resolve():
                        return True
                except Exception:
                    pass
        return False
    except Exception:
        return False




def signature_dir() -> Path:
    return _SIG_DIR


@lru_cache(maxsize=1)
def load_signatures() -> frozenset[str]:
    """
    Load all SHA-256 malware hashes from signatures/*.txt into memory.
    Lines may end with ';' — stripped. Invalid lines ignored.
    """
    hashes: set[str] = set()
    if not _SIG_DIR.is_dir():
        return frozenset()

    for path in sorted(_SIG_DIR.glob("*.txt")):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    h = line.strip().rstrip(";").lower()
                    if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                        hashes.add(h)
        except OSError:
            continue
    return frozenset(hashes)


def signature_stats() -> dict:
    sigs = load_signatures()
    packs = list(_SIG_DIR.glob("*.txt")) if _SIG_DIR.is_dir() else []
    return {
        "count": len(sigs),
        "packs": len(packs),
        "dir": str(_SIG_DIR),
    }


def sha256_file(path: str | Path, max_size: int = MAX_HASH_BYTES) -> str | None:
    """Return lowercase SHA-256 hex digest, or None if unreadable/too large."""
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > max_size:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 256)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def check_hash(digest: str, signatures: frozenset[str] | None = None) -> bool:
    if not digest:
        return False
    sigs = signatures if signatures is not None else load_signatures()
    return digest.lower() in sigs


def scan_file(path: str | Path) -> dict:
    """
    Scan one file against the local SHA-256 database.

    Returns:
      {
        path, status: clean|infected|error|skipped,
        sha256, detail
      }
    """
    path = Path(path)
    result = {
        "path": str(path),
        "status": "error",
        "sha256": "",
        "detail": "",
    }
    if not path.is_file():
        result["detail"] = "not a regular file"
        return result

    if is_self_path(path):
        result["status"] = "skipped"
        result["detail"] = "ARIES project / signature file (excluded)"
        return result

    digest = sha256_file(path)
    if digest is None:
        result["status"] = "skipped"
        result["detail"] = "unreadable or exceeds size limit"
        return result

    result["sha256"] = digest
    sigs = load_signatures()
    if not sigs:
        result["status"] = "error"
        result["detail"] = f"no signatures loaded from {_SIG_DIR}"
        return result

    if check_hash(digest, sigs):
        result["status"] = "infected"
        result["detail"] = "SHA-256 matched local malware signature"
    else:
        result["status"] = "clean"
        result["detail"] = "no signature match"
    return result


def scan_paths(
    paths: Iterable[str | Path],
    *,
    on_progress=None,
) -> list[dict]:
    """Scan many paths; optional on_progress(i, total, path, result)."""
    paths = list(paths)
    total = len(paths)
    # warm cache once
    load_signatures()
    results = []
    for i, path in enumerate(paths):
        r = scan_file(path)
        results.append(r)
        if on_progress:
            on_progress(i + 1, total, str(path), r)
    return results


def scan_tree(
    root: str | Path,
    *,
    max_files: int = 20_000,
    on_progress=None,
) -> list[dict]:
    """Walk a directory tree and scan regular files."""
    root = Path(root)
    files: list[Path] = []
    if root.is_file():
        files = [root]
    elif root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # skip heavy/virtual
            dirnames[:] = [
                d
                for d in dirnames
                if d not in {"proc", "sys", "dev", "run", ".git", "node_modules"}
            ]
            for name in filenames:
                files.append(Path(dirpath) / name)
                if len(files) >= max_files:
                    break
            if len(files) >= max_files:
                break
    return scan_paths(files, on_progress=on_progress)
