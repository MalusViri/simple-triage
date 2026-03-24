"""Hashing helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path


def compute_hashes(path: Path, chunk_size: int = 8192) -> dict[str, str]:
    """Compute MD5, SHA1, and SHA256 for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
