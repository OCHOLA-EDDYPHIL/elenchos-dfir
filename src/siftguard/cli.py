from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from siftguard import __version__
from siftguard.audit.execution_ledger import read_events
from siftguard.evidence.hashing import sha256_file
from siftguard.evidence.manifest import build_manifest, write_manifest
from siftguard.parser.result import ParserResult
from siftguard.policy.paths import validate_output_path
from siftguard.workflows.correlation import run_correlation_workflow

PARSER_STATUS_EXIT_CODES = {
    "success": 0,
    "partial_success": 2,
    "skipped": 3,
    "failed": 1,
}


def _add_parser_result_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--case-id", required=True, help="Case identifier")
    parser.add_argument("--artifact-id", required=True, help="Source artifact identifier")
    parser.add_argument("--runs-root", type=Path, required=True, help="Parser runs root")
    parser.add_argument("--evidence-root", type=Path, help="Evidence root for output safety checks")
    parser.add_argument("--ledger-path", type=Path, help="Audit ledger JSONL path")
    parser.add_argument("--json-out", type=Path, help="Write ParserResult JSON under runs root")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=900,
        help="Parser timeout in seconds",
    )


def _parser_exit_code(result: ParserResult) -> int:
    return PARSER_STATUS_EXIT_CODES.get(result.status, 1)


def _parser_result_json(result: ParserResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)


def _emit_parser_result(
    result: ParserResult,
    *,
    json_out: Path | None,
    runs_root: Path,
    evidence_root: Path | None,
) -> int:
    payload = _parser_result_json(result)
    if json_out is None:
        print(payload)
        return _parser_exit_code(result)

    resolved_json_out = validate_output_path(json_out, runs_root, evidence_root)
    resolved_json_out.parent.mkdir(parents=True, exist_ok=True)
    resolved_json_out.write_text(payload + "\n", encoding="utf-8")
    print(f"status={result.status}")
    print(f"parser={result.parser_name}")
    print(f"events={len(result.events)}")
    print(f"result={resolved_json_out}")
    return _parser_exit_code(result)


def _run_parser_command(args: argparse.Namespace) -> int:
    try:
        if args.command == "parse-mft":
            from siftguard.parser import mft

            result = mft.parse_mft(
                case_id=args.case_id,
                artifact_id=args.artifact_id,
                mft_path=args.mft_path,
                runs_root=args.runs_root,
                evidence_root=args.evidence_root,
                ledger_path=args.ledger_path,
                timeout_seconds=args.timeout_seconds,
            )
        elif args.command == "parse-registry-runkeys":
            from siftguard.parser import registry_runkeys

            result = registry_runkeys.parse_registry_runkeys(
                case_id=args.case_id,
                artifact_id=args.artifact_id,
                hive_path=args.hive_path,
                runs_root=args.runs_root,
                artifact_type=args.artifact_type,
                evidence_root=args.evidence_root,
                ledger_path=args.ledger_path,
                timeout_seconds=args.timeout_seconds,
            )
        elif args.command == "parse-amcache":
            from siftguard.parser import amcache

            result = amcache.parse_amcache(
                case_id=args.case_id,
                artifact_id=args.artifact_id,
                amcache_path=args.amcache_path,
                runs_root=args.runs_root,
                evidence_root=args.evidence_root,
                ledger_path=args.ledger_path,
                timeout_seconds=args.timeout_seconds,
            )
        else:
            raise ValueError(f"unsupported parser command: {args.command}")
        return _emit_parser_result(
            result,
            json_out=args.json_out,
            runs_root=args.runs_root,
            evidence_root=args.evidence_root,
        )
    except Exception as exc:
        print(f"error={exc}", file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="siftguard", description="SIFTGuard CLI")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    hash_parser = subparsers.add_parser("hash", help="Compute SHA256 for a file")
    hash_parser.add_argument("file", type=Path, help="Path to file")

    inventory_parser = subparsers.add_parser("inventory", help="Inventory case artifacts")
    inventory_parser.add_argument("case_dir", type=Path, help="Path to case directory")
    inventory_parser.add_argument(
        "--manifest-out",
        type=Path,
        required=True,
        help="Write manifest JSON to this path",
    )

    audit_read_parser = subparsers.add_parser("audit-read", help="Read audit JSONL ledger")
    audit_read_parser.add_argument("ledger_path", type=Path, help="Path to audit ledger JSONL")

    parse_mft_parser = subparsers.add_parser("parse-mft", help="Run the MFTECmd MFT wrapper")
    _add_parser_result_args(parse_mft_parser)
    parse_mft_parser.add_argument("--mft-path", type=Path, required=True, help="Path to $MFT")

    parse_registry_parser = subparsers.add_parser(
        "parse-registry-runkeys",
        help="Run the constrained RECmd Run Key wrapper",
    )
    _add_parser_result_args(parse_registry_parser)
    parse_registry_parser.add_argument(
        "--hive-path",
        type=Path,
        required=True,
        help="Path to SOFTWARE or NTUSER.DAT hive",
    )
    parse_registry_parser.add_argument(
        "--artifact-type",
        default="registry_hive",
        choices=("registry_hive", "registry"),
        help="Input artifact type",
    )

    parse_amcache_parser = subparsers.add_parser(
        "parse-amcache",
        help="Run the AmcacheParser wrapper",
    )
    _add_parser_result_args(parse_amcache_parser)
    parse_amcache_parser.add_argument(
        "--amcache-path",
        type=Path,
        required=True,
        help="Path to Amcache.hve",
    )

    correlate_parser = subparsers.add_parser(
        "correlate",
        help="Build timelines, validated findings, and a Markdown report from normalized JSON",
    )
    correlate_parser.add_argument("--case-id", required=True, help="Case identifier")
    correlate_parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Existing normalized parser output JSON",
    )
    correlate_parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help=(
            "Generated workflow output directory under runs/, outputs/, analysis/, "
            "or reports/generated/"
        ),
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "hash":
        digest = sha256_file(args.file)
        print(digest)
        return 0

    if args.command == "inventory":
        manifest = build_manifest(args.case_dir)
        write_manifest(manifest, args.manifest_out)
        print(f"case_id={manifest.case_id}")
        print(f"artifact_count={manifest.artifact_count}")
        print(f"manifest={args.manifest_out}")
        return 0

    if args.command == "audit-read":
        events = read_events(args.ledger_path)
        print(f"events={len(events)}")
        for event in events:
            print(
                f"{event.get('event_id')} status={event.get('status')} "
                f"tool={event.get('tool_name')} exit_code={event.get('exit_code')}"
            )
        return 0

    if args.command in {"parse-mft", "parse-registry-runkeys", "parse-amcache"}:
        return _run_parser_command(args)

    if args.command == "correlate":
        try:
            result = run_correlation_workflow(
                case_id=args.case_id,
                input_path=args.input,
                output_dir=args.output_dir,
            )
        except Exception as exc:
            print(f"error={exc}", file=sys.stderr)
            return 1

        print(f"case_id={result.case_id}")
        print(f"output_dir={result.output_dir}")
        print(f"events={result.event_count}")
        print(f"timelines={result.timeline_count}")
        print(f"findings={result.finding_count}")
        print(f"timelines_path={result.timelines_path}")
        print(f"findings_path={result.findings_path}")
        print(f"report_path={result.report_path}")
        print(f"audit_path={result.audit_path}")
        return 0

    parser.print_help()
    return 0
