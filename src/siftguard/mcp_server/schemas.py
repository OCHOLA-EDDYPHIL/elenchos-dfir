from __future__ import annotations

from dataclasses import dataclass

TOOL_NAMES = [
    "create_case",
    "hash_evidence",
    "inventory_artifacts",
    "parse_mft",
    "parse_registry_runkeys",
    "parse_amcache",
    "correlate_timeline",
    "validate_findings",
    "generate_report",
]


@dataclass(slots=True)
class ToolDescriptor:
    name: str
    description: str
