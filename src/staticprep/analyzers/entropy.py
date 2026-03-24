"""Entropy helpers."""

from __future__ import annotations

import math


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy for a byte sequence."""
    if not data:
        return 0.0

    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)
