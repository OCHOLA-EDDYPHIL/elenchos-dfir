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


def test_openclaw_elenchos_smoke_runs_in_dry_run_mode(tmp_path: Path):
    output_dir = tmp_path / "runs" / "openclaw-smoke"
    result = subprocess.run(
        [
            str(repo_root() / ".venv" / "bin" / "python"),
            str(repo_root() / "scripts" / "openclaw_elenchos_smoke.py"),
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
    assert (output_dir / "agent-run" / "self_correction_events.json").is_file()


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
    assert ".venv/bin/python -m elenchos.integrations.mcp_server" in mcp_docs
    assert ".venv/bin/python -m elenchos.integrations.mcp_server" in readme
    assert "scripts/openclaw_elenchos_smoke.py --dry-run" in mcp_docs
    assert "scripts/openclaw_elenchos_smoke.py --dry-run" in readme
    assert "scripts/demo_elenchos_preflight.py" in mcp_docs
    assert "examples/openclaw/case-triage.prompt.md" in readme
    assert "examples/openclaw/case-triage.prompt.md" in mcp_docs
    assert "Casebook Selection" in mcp_docs
    assert "docs/casebooks/generic-windows-disk-triage.json" in mcp_docs
    assert "reusable_template: true" in mcp_docs
    assert "docs/casebooks/generic-windows-disk-triage.json" in readme
    assert ("docs/demo/openclaw-rocba-gap-" + "demo-prompt.md") not in readme
    assert ("docs/demo/openclaw-gap-self-" + "correction-runbook.md") not in readme
    assert "self_correction_events.json" in mcp_docs
    assert "casebooks may define claim-boundary metadata" in mcp_docs.casefold()
    assert "Bounded tools" in readme
    assert ".venv/bin/python -m elenchos case prepare ..." in readme
    assert ".venv/bin/python -m elenchos agent run-case ..." in readme


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


def test_openclaw_case_triage_prompt_is_bounded_and_claim_safe():
    prompt = (
        repo_root() / "examples" / "openclaw" / "case-triage.prompt.md"
    ).read_text(encoding="utf-8")
    lowered = prompt.casefold()
    collapsed = " ".join(prompt.split())
    analyst_prompt = prompt.split("## Host instruction", maxsplit=1)[0]

    for tool_name in (
        "prepare_case",
        "run_case",
        "summarize_run",
        "validate_run_outputs",
    ):
        assert tool_name in prompt
    assert "bounded Elenchos MCP/tool-adapter surface" in prompt
    assert "do not run raw shell commands" in lowered
    assert "do not run destructive commands" in lowered
    assert "do not write to evidence" in lowered
    assert "No OpenClaw or model output is forensic evidence" in prompt
    assert "docs/casebooks/generic-windows-disk-triage.json" in prompt
    assert "Do not invent case allegations" in collapsed
    assert "repeat the generated final_wording and scope_boundary exactly" in collapsed
    assert len(analyst_prompt.split()) < 80
    assert ("Elenchos proves " + "theft") not in prompt
    assert ("Elenchos proves " + "exfiltration") not in prompt
    assert ("courtroom" + "-ready") not in lowered


def test_openclaw_presentation_specific_demo_docs_are_not_tracked():
    root = repo_root()
    assert not (
        root / "docs" / "demo" / ("openclaw-rocba-gap-" + "demo-prompt.md")
    ).exists()
    assert not (
        root / "docs" / "demo" / ("openclaw-gap-self-" + "correction-runbook.md")
    ).exists()


def test_rocba_question_ids_are_not_hardcoded_in_source():
    root = repo_root()
    forbidden_terms = (
        "q_what_was_stolen",
        "q_where_transferred",
        "q_how_stolen",
        "q_memory",
    )
    hits: list[str] = []
    for path in sorted((root / "src").rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for term in forbidden_terms:
            if term in text:
                hits.append(f"{path.relative_to(root)}: {term}")

    assert hits == []


def test_public_docs_do_not_hardcode_local_home_paths():
    root = repo_root()
    public_forbidden_terms = ("/home/sansforensics", "/home/")
    paths = _text_files_under(
        root,
        (
            "README.md",
            "docs",
            "examples",
            "src",
            "scripts",
        ),
    )
    hits: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for term in public_forbidden_terms:
            if term in text:
                hits.append(f"{path.relative_to(root)}: {term}")

    assert hits == []

    stale_user_hits: list[str] = []
    stale_user = "nyama" + "bites"
    public_paths = ("README.md", "docs", "examples", "src", "scripts", "tests")
    for path in _text_files_under(root, public_paths):
        if stale_user in path.read_text(encoding="utf-8", errors="ignore"):
            stale_user_hits.append(str(path.relative_to(root)))

    assert stale_user_hits == []
