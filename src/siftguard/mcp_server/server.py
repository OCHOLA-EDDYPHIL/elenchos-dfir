"""MCP server placeholder.

This module intentionally does not expose arbitrary shell execution and does not
require MCP runtime dependencies for import-time behavior.
"""

from __future__ import annotations

from siftguard.mcp_server.schemas import TOOL_NAMES


def get_planned_tools() -> list[str]:
    return list(TOOL_NAMES)


def create_server() -> None:
    raise RuntimeError(
        "MCP server runtime is not wired yet. Typed tool handlers will be completed incrementally."
    )
