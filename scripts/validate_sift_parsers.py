#!/usr/bin/env python3
# ruff: noqa: E402
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from siftguard.audit.execution_ledger import read_events
from siftguard.parser.amcache import parse_amcache
from siftguard.parser.mft import parse_mft
from siftguard.parser.registry_runkeys import parse_registry_runkeys
from siftguard.parser.result import ParserResult
from siftguard.policy.paths import is_relative_to, validate_output_path

LOCAL_ENV_PATH = Path(".local/sift-validation/paths.env")
VALIDATION_TOOLS = ("MFTECmd", "RECmd", "AmcacheParser")
DEFAULT_CASE_ID = "CASE-PARSER-VALIDATION"
SUMMARY_FILENAME = "sift-parser-validation-summary.json"


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _strip_env_value(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return stripped[1:-1]
    return stripped


def read_local_env_file(path: Path = LOCAL_ENV_PATH) -> dict[str, str]:
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, raw_value = stripped.split("=", 1)
            values[key.strip()] = _strip_env_value(raw_value)
    return values


def split_registry_hive_paths(value: str | None) -> list[Path]:
    if not value:
        return []

    paths: list[Path] = []
    for line in value.splitlines():
        for part in line.split(":"):
            item = part.strip()
            if item:
                paths.append(Path(item))
    return paths


def load_validation_defaults(
    environ: dict[str, str] | None = None,
    local_env_path: Path = LOCAL_ENV_PATH,
) -> dict[str, Any]:
    env = os.environ if environ is None else environ
    local_values = read_local_env_file(local_env_path)

    def get_value(name: str) -> str | None:
        return env.get(name) or local_values.get(name)

    defaults: dict[str, Any] = {}
    evidence_root = get_value("SIFTGUARD_VALIDATION_EVIDENCE_ROOT")
    if evidence_root:
        defaults["evidence_root"] = Path(evidence_root)

    mft_path = get_value("SIFTGUARD_VALIDATION_MFT_PATH")
    if mft_path:
        defaults["mft_path"] = Path(mft_path)

    registry_paths = split_registry_hive_paths(
        get_value("SIFTGUARD_VALIDATION_REGISTRY_HIVE_PATHS")
    )
    if registry_paths:
        defaults["registry_hive_paths"] = registry_paths

    amcache_path = get_value("SIFTGUARD_VALIDATION_AMCACHE_PATH")
    if amcache_path:
        defaults["amcache_path"] = Path(amcache_path)

    return defaults


def build_arg_parser(defaults: dict[str, Any] | None = None) -> argparse.ArgumentParser:
    resolved_defaults = defaults or {}
    parser = argparse.ArgumentParser(
        description="Validate SIFTGuard parser wrappers against supplied local SIFT evidence."
    )
    parser.add_argument("--case-id", default=DEFAULT_CASE_ID, help="Validation case ID")
    parser.add_argument(
        "--runs-root",
        type=Path,
        required=True,
        help="Local runs root for validation outputs",
    )
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=resolved_defaults.get("evidence_root"),
        required=resolved_defaults.get("evidence_root") is None,
        help="Local evidence root; evidence remains read-only",
    )
    parser.add_argument(
        "--mft-path",
        type=Path,
        default=resolved_defaults.get("mft_path"),
        help="Optional local $MFT path",
    )
    parser.add_argument(
        "--registry-hive-path",
        type=Path,
        action="append",
        default=None,
        help="Optional local SOFTWARE or NTUSER.DAT hive path; repeatable",
    )
    parser.add_argument(
        "--amcache-path",
        type=Path,
        default=resolved_defaults.get("amcache_path"),
        help="Optional local Amcache.hve path",
    )
    parser.add_argument(
        "--summary-out",
        type=Path,
        help="Validation summary JSON path under runs root",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=900,
        help="Parser timeout in seconds",
    )
    return parser


def parse_args(
    argv: list[str] | None = None,
    defaults: dict[str, Any] | None = None,
) -> argparse.Namespace:
    resolved_defaults = defaults or {}
    args = build_arg_parser(resolved_defaults).parse_args(argv)
    if args.registry_hive_path is None:
        args.registry_hive_path = list(resolved_defaults.get("registry_hive_paths", []))
    return args


def _read_os_pretty_name(os_release_path: Path = Path("/etc/os-release")) -> str | None:
    if not os_release_path.exists():
        return None
    for line in os_release_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("PRETTY_NAME="):
            return _strip_env_value(line.split("=", 1)[1])
    return None


def collect_environment() -> dict[str, str | None]:
    return {
        "date_utc": utc_now_z(),
        "os": _read_os_pretty_name(),
        "kernel": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
    }


def _version_text(stdout: str, stderr: str) -> str | None:
    combined = "\n".join([stdout, stderr])
    for line in combined.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:240]
    return None


def collect_tool_info() -> dict[str, dict[str, Any]]:
    tools: dict[str, dict[str, Any]] = {}
    for tool in VALIDATION_TOOLS:
        found = shutil.which(tool)
        info: dict[str, Any] = {
            "available": found is not None,
            "path": "on PATH" if found else None,
            "version": None,
            "version_exit_code": None,
        }
        if found:
            try:
                completed = subprocess.run(
                    [tool, "--version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                info["version_exit_code"] = completed.returncode
                info["version"] = _version_text(completed.stdout, completed.stderr)
            except (OSError, subprocess.TimeoutExpired) as exc:
                info["version"] = f"version probe failed: {type(exc).__name__}"
        tools[tool] = info
    return tools


def resolve_summary_out(
    summary_out: Path | None,
    runs_root: Path,
    evidence_root: Path | None,
    case_id: str,
) -> Path:
    candidate = summary_out or Path(case_id) / SUMMARY_FILENAME
    if (
        summary_out is not None
        and not candidate.is_absolute()
        and candidate.parts
        and candidate.parts[0] == runs_root.name
    ):
        candidate = candidate.resolve()
    resolved_summary = validate_output_path(candidate, runs_root, evidence_root)
    case_root = (runs_root / case_id).resolve()
    if not is_relative_to(resolved_summary, case_root):
        raise ValueError("summary output path must be under runs/<case_id>")
    return resolved_summary


def sanitized_runs_path(path: Path | str | None, runs_root: Path) -> str | None:
    if path is None:
        return None
    resolved_path = Path(path).resolve()
    resolved_runs_root = runs_root.resolve()
    if not is_relative_to(resolved_path, resolved_runs_root):
        return Path(path).name
    return str(Path("runs") / resolved_path.relative_to(resolved_runs_root))


def output_basenames(paths: list[str]) -> list[str]:
    return sorted({Path(path).name for path in paths})


def summarize_parser_result(
    result: ParserResult,
    *,
    runs_root: Path,
    audit_ledger_path: Path,
) -> dict[str, Any]:
    return {
        "parser_name": result.parser_name,
        "artifact_id": result.artifact_id,
        "artifact_type": result.artifact_type,
        "status": result.status,
        "event_count": len(result.events),
        "warning_count": len(result.warnings),
        "error_count": len(result.errors),
        "output_file_count": len(result.output_files),
        "output_file_basenames": output_basenames(result.output_files),
        "output_dir": sanitized_runs_path(result.output_dir, runs_root),
        "audit_ledger_path": sanitized_runs_path(audit_ledger_path, runs_root),
    }


def validation_failure_row(
    *,
    parser_name: str,
    artifact_id: str,
    artifact_type: str,
    audit_ledger_path: Path,
    runs_root: Path,
) -> dict[str, Any]:
    return {
        "parser_name": parser_name,
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "status": "failed",
        "event_count": 0,
        "warning_count": 0,
        "error_count": 1,
        "output_file_count": 0,
        "output_file_basenames": [],
        "output_dir": None,
        "audit_ledger_path": sanitized_runs_path(audit_ledger_path, runs_root),
    }


def _artifact_is_usable(path: Path | None, evidence_root: Path) -> bool:
    if path is None or not path.exists() or not path.is_file():
        return False
    return is_relative_to(path.resolve(), evidence_root.resolve())


def _summary_exit_code(summary: dict[str, Any]) -> int:
    validations = list(summary.get("validations", []))
    if not validations:
        return 1
    eventful = [row for row in validations if int(row.get("event_count", 0)) > 0]
    if len(eventful) == len(validations) and all(
        row.get("status") == "success" for row in validations
    ):
        return 0
    if eventful:
        return 2
    return 1


def run_validation(args: argparse.Namespace) -> tuple[dict[str, Any], Path, int]:
    runs_root = Path(args.runs_root)
    evidence_root = Path(args.evidence_root)
    if not evidence_root.exists() or not evidence_root.is_dir():
        raise FileNotFoundError("evidence_root must exist and be a directory")
    if is_relative_to(runs_root.resolve(), evidence_root.resolve()):
        raise ValueError("runs_root must not be inside evidence_root")

    runs_root.mkdir(parents=True, exist_ok=True)
    summary_path = resolve_summary_out(args.summary_out, runs_root, evidence_root, args.case_id)
    ledger_path = validate_output_path(Path(args.case_id) / "audit.jsonl", runs_root, evidence_root)

    summary: dict[str, Any] = {
        "case_id": args.case_id,
        "generated_at_utc": utc_now_z(),
        "environment": collect_environment(),
        "tools": collect_tool_info(),
        "validations": [],
        "audit": {
            "ledger_path": sanitized_runs_path(ledger_path, runs_root),
            "entry_count": 0,
        },
        "errors": [],
    }

    supplied_any = bool(args.mft_path or args.registry_hive_path or args.amcache_path)
    if not supplied_any:
        summary["errors"].append("no parser artifact paths supplied")

    if args.mft_path is not None:
        artifact_id = "EV-MFT-VALIDATION"
        if _artifact_is_usable(args.mft_path, evidence_root):
            result = parse_mft(
                case_id=args.case_id,
                artifact_id=artifact_id,
                mft_path=args.mft_path,
                runs_root=runs_root,
                evidence_root=evidence_root,
                ledger_path=ledger_path,
                timeout_seconds=args.timeout_seconds,
            )
            summary["validations"].append(
                summarize_parser_result(result, runs_root=runs_root, audit_ledger_path=ledger_path)
            )
        else:
            summary["errors"].append("MFT artifact path is unavailable or outside evidence_root")
            summary["validations"].append(
                validation_failure_row(
                    parser_name="mftecmd",
                    artifact_id=artifact_id,
                    artifact_type="mft",
                    audit_ledger_path=ledger_path,
                    runs_root=runs_root,
                )
            )

    for index, hive_path in enumerate(args.registry_hive_path, start=1):
        artifact_id = f"EV-REG-VALIDATION-{index}"
        if _artifact_is_usable(hive_path, evidence_root):
            result = parse_registry_runkeys(
                case_id=args.case_id,
                artifact_id=artifact_id,
                hive_path=hive_path,
                runs_root=runs_root,
                evidence_root=evidence_root,
                ledger_path=ledger_path,
                timeout_seconds=args.timeout_seconds,
            )
            summary["validations"].append(
                summarize_parser_result(result, runs_root=runs_root, audit_ledger_path=ledger_path)
            )
        else:
            summary["errors"].append("Registry hive path is unavailable or outside evidence_root")
            summary["validations"].append(
                validation_failure_row(
                    parser_name="recmd",
                    artifact_id=artifact_id,
                    artifact_type="registry",
                    audit_ledger_path=ledger_path,
                    runs_root=runs_root,
                )
            )

    if args.amcache_path is not None:
        artifact_id = "EV-AMCACHE-VALIDATION"
        if _artifact_is_usable(args.amcache_path, evidence_root):
            result = parse_amcache(
                case_id=args.case_id,
                artifact_id=artifact_id,
                amcache_path=args.amcache_path,
                runs_root=runs_root,
                evidence_root=evidence_root,
                ledger_path=ledger_path,
                timeout_seconds=args.timeout_seconds,
            )
            summary["validations"].append(
                summarize_parser_result(result, runs_root=runs_root, audit_ledger_path=ledger_path)
            )
        else:
            summary["errors"].append(
                "Amcache artifact path is unavailable or outside evidence_root"
            )
            summary["validations"].append(
                validation_failure_row(
                    parser_name="amcacheparser",
                    artifact_id=artifact_id,
                    artifact_type="amcache",
                    audit_ledger_path=ledger_path,
                    runs_root=runs_root,
                )
            )

    summary["audit"]["entry_count"] = len(read_events(ledger_path))
    exit_code = _summary_exit_code(summary)
    summary["exit_code"] = exit_code
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary, summary_path, exit_code


def print_summary(summary: dict[str, Any], summary_path: Path, runs_root: Path) -> None:
    print(f"summary={sanitized_runs_path(summary_path, runs_root)}")
    for row in summary["validations"]:
        print(
            " ".join(
                [
                    f"parser={row['parser_name']}",
                    f"artifact={row['artifact_id']}",
                    f"status={row['status']}",
                    f"events={row['event_count']}",
                    f"warnings={row['warning_count']}",
                    f"errors={row['error_count']}",
                ]
            )
        )
    if summary["errors"]:
        print(f"validation_errors={len(summary['errors'])}")


def main(argv: list[str] | None = None) -> int:
    defaults = load_validation_defaults()
    args = parse_args(argv, defaults)
    try:
        summary, summary_path, exit_code = run_validation(args)
    except Exception as exc:
        print(f"error={exc}", file=sys.stderr)
        return 1
    print_summary(summary, summary_path, Path(args.runs_root))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
