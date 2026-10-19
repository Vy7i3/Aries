"""
ARIES malware engine (original implementation).

Design ideas studied from common open-source hash scanners
(SHA-256 lookup against local signature packs; optional VT-style
size limits for remote APIs are not required here):

  - Compute SHA-256 of each file
  - Match against local signature sets (one hash per line;
    optional trailing ';' metadata is ignored)
  - Report threat / clean / error

No third-party GUI or GPL application source is included.
Signature packs may be dropped into:
  - <project>/aries/signatures/
  - ~/.local/share/aries/signatures/
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from dataclasses import dataclass, field

# Well-known EICAR test file SHA-256 (public test string)
_EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf146d5b0"

MAX_HASH_BYTES = 64 * 1024 * 1024  # 64 MiB per file for hash matching


@dataclass
class AVHit:
    path: str
    sha256: str
    threat: str  # signature name or "known-malware-hash"


@dataclass
class AVScanResult:
    scanned: int = 0
    clean: int = 0
    infected: int = 0
    errors: int = 0
    skipped: int = 0
    hits: list[AVHit] = field(default_factory=list)
    signatures_loaded: int = 0


class HashDatabase:
    """In-memory set of malicious SHA-256 digests."""

    def __init__(self) -> None:
        self._hashes: set[str] = set()
        self._meta: dict[str, str] = {}

    def __len__(self) -> int:
        return len(self._hashes)

    def add(self, digest: str, name: str = "known-malware-hash") -> None:
        d = digest.strip().lower()
        if len(d) == 64 and all(c in "0123456789abcdef" for c in d):
            self._hashes.add(d)
            self._meta[d] = name

    def load_file(self, path: Path) -> int:
        """Load hashes from a text pack. Format: hash or hash;name per line."""
        added = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # support "hash;" or "hash;label"
                    part = line.split(";", 1)[0].strip().lower()
                    label = "known-malware-hash"
                    if ";" in line:
                        rest = line.split(";", 1)[1].strip()
                        if rest:
                            label = rest[:80]
                    before = len(self._hashes)
                    self.add(part, label)
                    if len(self._hashes) > before:
                        added += 1
        except OSError:
            return 0
        return added

    def lookup(self, digest: str) -> str | None:
        d = digest.lower()
        if d in self._hashes:
            return self._meta.get(d, "known-malware-hash")
        return None


def default_signature_dirs() -> list[Path]:
    here = Path(__file__).resolve().parent / "signatures"
    user = Path.home() / ".local" / "share" / "aries" / "signatures"
    return [here, user]


def load_database(extra_dirs: list[Path] | None = None) -> HashDatabase:
    db = HashDatabase()
    db.add(_EICAR_SHA256, "EICAR-Test-File")

    dirs = default_signature_dirs()
    if extra_dirs:
        dirs.extend(extra_dirs)

    for d in dirs:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.txt")):
            db.load_file(path)
        for path in sorted(d.glob("*.hash")):
            db.load_file(path)

    return db


def sha256_file(path: str, max_bytes: int = MAX_HASH_BYTES) -> str | None:
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
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


def scan_file(path: str, db: HashDatabase | None = None) -> AVHit | None:
    """Return AVHit if malicious hash matches, else None. Raises nothing."""
    if db is None:
        db = load_database()
    digest = sha256_file(path)
    if not digest:
        return None
    name = db.lookup(digest)
    if name:
        return AVHit(path=path, sha256=digest, threat=name)
    return None


def scan_paths(
    paths: list[str],
    db: HashDatabase | None = None,
    on_progress: callable | None = None,
) -> AVScanResult:
    if db is None:
        db = load_database()
    result = AVScanResult(signatures_loaded=len(db))
    total = len(paths)
    for i, path in enumerate(paths):
        if on_progress:
            on_progress(i + 1, total, path)
        if not os.path.isfile(path):
            result.skipped += 1
            continue
        try:
            digest = sha256_file(path)
            if digest is None:
                result.skipped += 1
                continue
            result.scanned += 1
            name = db.lookup(digest)
            if name:
                result.infected += 1
                result.hits.append(AVHit(path=path, sha256=digest, threat=name))
            else:
                result.clean += 1
        except OSError:
            result.errors += 1
    return result
