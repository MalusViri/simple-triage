"""Tests for hashing helpers."""

from __future__ import annotations

import hashlib

from staticprep.analyzers.hashes import compute_hashes


def test_compute_hashes(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"staticprep")

    result = compute_hashes(sample)

    assert result == {
        "md5": hashlib.md5(b"staticprep").hexdigest(),
        "sha1": hashlib.sha1(b"staticprep").hexdigest(),
        "sha256": hashlib.sha256(b"staticprep").hexdigest(),
    }
