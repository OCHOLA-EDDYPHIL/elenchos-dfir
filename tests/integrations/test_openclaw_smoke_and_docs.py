from __future__ import annotations

import subprocess
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _text_files_under(root: Path, names: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for name in names:
        path = root / name
        if path.is_file():
            files.append(path)
            continue
        if path.is_dir():
            files.extend(
                sorted(
                    candidate
                    for candidate in path.rglob("*")
                    if candidate.is_file() and "__pycache__" not in candidate.parts
                )
            )
    return files


def test_openclaw_siftguard_smoke_runs_in_dry_run_mode(tmp_path: Path):
    output_dir = tmp_path / "runs" / "openclaw-smoke"
    result = subprocess.run(
        [
            str(repo_root() / ".venv" / "bin" / "python"),
            str(repo_root() / "scripts" / "openclaw_siftguard_smoke.py"),
            "--dry-run",
            "--output-dir",
            str(output_dir),
        ],
        cwd=repo_root(),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "validation_status=pass" in result.stdout
    assert (output_dir / "openclaw-trace" / "prepare_case.stdout").is_file()
    assert (output_dir / "openclaw-trace" / "run_case.stderr").is_file()
    assert (output_dir / "openclaw-trace" / "summary.json").is_file()


def test_openclaw_docs_state_model_agnostic_core_and_provider_config():
    docs = (repo_root() / "docs" / "openclaw-mcp-workflow.md").read_text(encoding="utf-8")
    readme = (repo_root() / "README.md").read_text(encoding="utf-8")
    combined = f"{docs}\n{readme}".casefold()

    assert "model-agnostic" in combined
    assert "openclaw controls provider and model selection" in combined
    assert "model output is not forensic evidence" in combined
    assert "prepare_case -> run_case -> summarize_run -> validate_run_outputs" in combined


def test_public_docs_and_code_do_not_reference_private_planning_source():
    root = repo_root()
    private_source_name = "dos" + "sier"
    forbidden_terms = (
        private_source_name,
        "Tactical " + "Build",
        "tactical " + private_source_name,
        "build " + private_source_name,
    )
    paths = _text_files_under(
        root,
        (
            "README.md",
            "docs",
            "src",
            "tests",
            "scripts",
            "pyproject.toml",
            ".env.example",
        ),
    )

    hits: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore").casefold()
        for term in forbidden_terms:
            if term.casefold() in text:
                hits.append(f"{path.relative_to(root)}: {term}")

    assert hits == []


def test_openclaw_legacy_files_are_removed():
    root = repo_root()
    deleted_paths = [
        root / "docs" / ("openclaw-agent-" + "workflow.md"),
        root / "scripts" / ("openclaw-agent-" + "smoke.sh"),
        root / "tests" / "unit" / "agent" / ("test_openclaw_agent_" + "smoke_script.py"),
        root / "docs" / "openclaw.md",
        root / "docs" / "openclaw-viability.md",
    ]

    assert [path for path in deleted_paths if path.exists()] == []


def test_openclaw_docs_and_readme_point_to_mcp_adapter_only():
    root = repo_root()
    mcp_docs = (root / "docs" / "openclaw-mcp-workflow.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert "Architecture role" in mcp_docs
    assert "Current repo implementation" in mcp_docs
    assert "The preferred integration path is the bounded MCP/tool adapter" in mcp_docs
    assert "Preferred final OpenClaw/MCP path" in readme
    assert ".venv/bin/python -m siftguard.integrations.mcp_server" in mcp_docs
    assert ".venv/bin/python -m siftguard.integrations.mcp_server" in readme
    assert "scripts/openclaw_siftguard_smoke.py --dry-run" in mcp_docs
    assert "scripts/openclaw_siftguard_smoke.py --dry-run" in readme
    assert "Bounded tools" in readme
    assert ".venv/bin/python -m siftguard case prepare ..." in readme
    assert ".venv/bin/python -m siftguard agent run-case ..." in readme


def test_no_legacy_openclaw_references_remain():
    root = repo_root()
    forbidden_terms = (
        "openclaw-agent-" + "smoke",
        "openclaw-agent-" + "workflow",
        "CASE-AGENT-" + "OPENCLAW-SMOKE",
        "fixed " + "smoke command",
        "synthetic " + "smoke command",
    )
    paths = _text_files_under(
        root,
        (
            "README.md",
            "docs",
            "src",
            "tests",
            "scripts",
            ".github",
        ),
    )

    hits: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore").casefold()
        for term in forbidden_terms:
            if term.casefold() in text:
                hits.append(f"{path.relative_to(root)}: {term}")

    assert hits == []
