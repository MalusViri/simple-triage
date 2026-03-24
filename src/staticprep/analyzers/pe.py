"""PE parsing helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import pefile
except ImportError:  # pragma: no cover - dependency may be absent in some environments
    pefile = None

from staticprep.analyzers.entropy import shannon_entropy
from staticprep.analyzers.imports import normalize_imports


def analyze_pe(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Analyze a PE file and return PE metadata and imports."""
    if pefile is None:
        raise RuntimeError("pefile is not installed")

    pe = pefile.PE(str(path), fast_load=False)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )

    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
        data = section.get_data()
        sections.append(
            {
                "name": name,
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "entropy": shannon_entropy(data),
            }
        )

    imports_by_dll: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore")
            apis = []
            for imported in entry.imports:
                if imported.name is None:
                    apis.append(f"ordinal_{imported.ordinal}")
                else:
                    apis.append(imported.name.decode("utf-8", errors="ignore"))
            imports_by_dll[dll_name] = apis

    pe_info = {
        "is_pe": True,
        "machine_type": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
        "compile_timestamp": datetime.fromtimestamp(
            pe.FILE_HEADER.TimeDateStamp, tz=UTC
        ).isoformat(),
        "subsystem": pefile.SUBSYSTEM_TYPE.get(
            pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem)
        ),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "number_of_sections": int(pe.FILE_HEADER.NumberOfSections),
        "sections": sections,
    }
    return pe_info, normalize_imports(imports_by_dll)
