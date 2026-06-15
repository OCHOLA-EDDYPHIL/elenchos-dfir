#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

EXPECTED_TOOLS = {
    "emit_claim_boundary",
    "evaluate_action_policy",
    "finish_case_run",
    "inspect_run_state",
    "poll_case_run",
    "prepare_case",
    "record_model_rationale",
    "run_case",
    "stop",
    "summarize_run",
    "start_case_run",
    "validate_run_outputs",
}
EXPECTED_LOCAL_TOOLS = (
    "MFTECmd",
    "RECmd",
    "AmcacheParser",
    "ewfinfo",
    "ewfmount",
    "mmls",
    "fls",
    "icat",
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _run(
    argv: list[str],
    *,
    cwd: Path,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )


def _print_check(name: str, ok: bool, detail: str) -> None:
    status = "PASS" if ok else "WARN"
    print(f"{status} {name}: {detail}")


def _mcp_tools(repo: Path) -> set[str]:
    request = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            "",
        ]
    )
    completed = _run(
        [str(repo / ".venv" / "bin" / "python"), "-m", "elenchos.integrations.mcp_server"],
        cwd=repo,
        input_text=request,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())

    tools: set[str] = set()
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        result = payload.get("result")
        if not isinstance(result, dict) or "tools" not in result:
            continue
        rows = result.get("tools")
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get("name"), str):
                    tools.add(row["name"])
    return tools


def _openclaw_mcp_config(repo: Path) -> dict[str, Any] | None:
    if shutil.which("openclaw") is None:
        return None
    completed = _run(["openclaw", "mcp", "list", "--json"], cwd=repo)
    if completed.returncode != 0:
        return None
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        return None
    value = payload.get("elenchos")
    return value if isinstance(value, dict) else None


def _openclaw_plugins() -> dict[str, Any]:
    config_path = Path.home() / ".openclaw" / "openclaw.json"
    if not config_path.is_file():
        return {}
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    plugins = payload.get("plugins")
    return plugins if isinstance(plugins, dict) else {}


def _openclaw_plugin_allowlist_status(plugins: dict[str, Any]) -> tuple[bool, str]:
    allowlist = plugins.get("allow")
    if isinstance(allowlist, list) and allowlist:
        allowed = ", ".join(str(name) for name in allowlist)
        return True, f"plugins.allow={allowed}"
    return (
        False,
        "plugins.allow is empty or missing; configure an explicit allowlist "
        "before recording the final demo",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check that the Elenchos demo uses the bounded MCP path."
    )
    parser.add_argument("--repo-root", type=Path, default=repo_root())
    args = parser.parse_args(argv)

    repo = args.repo_root.resolve()
    failures = 0

    _print_check("repo", repo.is_dir(), repo.as_posix())
    if not (repo / ".venv" / "bin" / "python").is_file():
        _print_check("venv", False, ".venv/bin/python is missing")
        return 1

    try:
        tools = _mcp_tools(repo)
    except Exception as exc:
        _print_check("mcp_tools", False, str(exc))
        return 1
    tools_ok = tools == EXPECTED_TOOLS
    failures += 0 if tools_ok else 1
    _print_check("mcp_tools", tools_ok, ", ".join(sorted(tools)))

    config = _openclaw_mcp_config(repo)
    if config is None:
        _print_check("openclaw_mcp", False, "OpenClaw MCP config not readable")
        failures += 1
    else:
        command = str(config.get("command", ""))
        cwd = str(config.get("cwd", ""))
        expected_command = str(repo / ".venv" / "bin" / "python")
        ok = command == expected_command and Path(cwd).resolve() == repo
        detail = f"command={command or '<missing>'} cwd={cwd or '<missing>'}"
        _print_check("openclaw_mcp", ok, detail)
        failures += 0 if ok else 1

    missing_tools = [name for name in EXPECTED_LOCAL_TOOLS if shutil.which(name) is None]
    local_ok = not missing_tools
    _print_check(
        "local_sift_tools",
        local_ok,
        "all present" if local_ok else f"missing: {', '.join(missing_tools)}",
    )
    failures += 0 if local_ok else 1

    plugins = _openclaw_plugins()
    allowlist_ok, allowlist_detail = _openclaw_plugin_allowlist_status(plugins)
    _print_check("openclaw_plugin_allowlist", allowlist_ok, allowlist_detail)

    entries = plugins.get("entries") if isinstance(plugins.get("entries"), dict) else {}
    enabled_plugins = sorted(
        name for name, row in entries.items() if isinstance(row, dict) and row.get("enabled")
    )
    broad = [name for name in enabled_plugins if name.casefold() in {"codex"}]
    _print_check(
        "openclaw_plugins",
        not broad,
        "enabled=" + (", ".join(enabled_plugins) if enabled_plugins else "none"),
    )

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
