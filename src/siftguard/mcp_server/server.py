"""MCP server placeholder.

This module intentionally does not expose arbitrary shell execution and does not
require MCP runtime dependencies for import-time behavior.
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from siftguard.mcp_server.schemas import TOOL_NAMES
from siftguard.workflows.correlation import run_correlation_workflow


def get_planned_tools() -> list[str]:
    return list(TOOL_NAMES)


def _required_string(request: Mapping[str, object], name: str) -> str:
    value = request.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_bool(request: Mapping[str, object], name: str, default: bool) -> bool:
    value = request.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def run_correlation_workflow_tool(request: Mapping[str, object]) -> dict[str, object]:
    result = run_correlation_workflow(
        case_id=_required_string(request, "case_id"),
        input_path=Path(_required_string(request, "normalized_events_path")),
        output_dir=Path(_required_string(request, "output_dir")),
        include_report=_optional_bool(request, "include_report", True),
    )
    return result.to_dict()


def create_server() -> None:
    raise RuntimeError(
        "MCP server runtime is not wired yet. Typed tool handlers will be completed incrementally."
    )
