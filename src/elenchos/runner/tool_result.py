from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ToolResult:
    command: list[str]
    cwd: str | None
    exit_code: int
    duration_ms: int
    stdout_path: str | None
    stderr_path: str | None
    stdout_sha256: str | None
    stderr_sha256: str | None
    status: str
