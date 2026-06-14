"""Tool version capture placeholder."""

from __future__ import annotations

from pathlib import Path


def write_tool_versions(output_path: Path, lines: list[str]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
