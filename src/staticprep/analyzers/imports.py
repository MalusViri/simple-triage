"""Import extraction helpers."""

from __future__ import annotations

from typing import Any


def normalize_imports(imports_by_dll: dict[str, list[str]]) -> dict[str, Any]:
    """Normalize imports into deterministic DLL and flattened API structures."""
    normalized = {
        dll: sorted(set(apis))
        for dll, apis in sorted(imports_by_dll.items(), key=lambda item: item[0].lower())
    }
    flat = sorted({api for apis in normalized.values() for api in apis})
    return {
        "by_dll": normalized,
        "flat": flat,
        "total_import_count": len(flat),
        "dll_count": len(normalized),
    }
