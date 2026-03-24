"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def fixture_dir() -> Path:
    """Return the repository fixtures directory."""
    return Path(__file__).parent / "fixtures"
