"""Encoding helpers for text normalization."""

from __future__ import annotations


def safe_decode(value: bytes, encoding: str = "utf-8") -> str:
    """Decode bytes while replacing invalid sequences."""
    return value.decode(encoding, errors="replace")
