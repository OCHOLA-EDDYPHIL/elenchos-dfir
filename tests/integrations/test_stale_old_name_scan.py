from __future__ import annotations

from pathlib import Path


def test_no_active_stale_old_names():
    root = Path(__file__).resolve().parents[2]
    ignored_parts = {
        ".git",
        ".venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "runs",
        ".local",
        ".openclaw",
        "." + "co" + "dex",
        "__pycache__",
    }
    needles = ["sift" + "guard", "SIFT" + "Guard", "SIFT" + "Guard MCP"]
    hits: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in ignored_parts for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in needles:
            if needle in text:
                hits.append(f"{path.relative_to(root)}: {needle}")
    assert hits == []
