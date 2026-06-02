from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from siftguard import __version__
from siftguard.agent.models import AgentRunStatus
from siftguard.agent.run_case import run_case_output_summary, run_case_workflow
from siftguard.agent.runner import run_agent_fixture_workflow, run_agent_workflow
from siftguard.audit.execution_ledger import read_events
from siftguard.case_prep.prepare import prepare_case
from siftguard.evidence.hashing import sha256_file
from siftguard.evidence.manifest import build_manifest, write_manifest
from siftguard.parser.result import ParserResult
from siftguard.policy.paths import validate_output_path
from siftguard.triage import SUPPORTED_EVENT_SELECTION_PROFILES
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

    case_parser = subparsers.add_parser(
        "case",
        help="Prepare case artifacts from read-only source evidence",
    )
    case_subparsers = case_parser.add_subparsers(dest="case_command")
    case_prepare_parser = case_subparsers.add_parser(
        "prepare",
        help="Discover sources or read a source manifest and generate case prep manifests",
        description=(
            "Prepare a read-only case by discovering source files or reading a JSON "
            "source manifest. --source-root discovers sources and writes a local JSON "
            "source manifest. --source-manifest uses an existing JSON source manifest. "
            "Memory sources are inventoried only unless future memory support is "
            "implemented. Generated outputs go under ignored run paths such as "
            "runs/, outputs/, analysis/, or reports/generated/."
        ),
    )
    case_prepare_parser.add_argument("--case-id", required=True, help="Case identifier")
    source_group = case_prepare_parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--source-root",
        type=Path,
        help=(
            "Discover source files under this read-only source root and write "
            "a JSON source manifest"
        ),
    )
    source_group.add_argument(
        "--source-manifest",
        type=Path,
        help="Use an existing JSON source manifest generated by SIFTGuard",
    )
    case_prepare_parser.add_argument(
        "--source-manifest-out",
        type=Path,
        help=(
            "Write the generated local JSON source manifest; allowed only with "
            "--source-root"
        ),
    )
    case_prepare_parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help=(
            "Generated case-prep output directory under runs/, outputs/, analysis/, "
            "or reports/generated/"
        ),
    )

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
        help="Generate timelines, validated findings, and a Markdown report from normalized JSON",
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

    agent_parser = subparsers.add_parser(
        "agent",
        help="Run constrained deterministic agent workflows",
    )
    agent_subparsers = agent_parser.add_subparsers(dest="agent_command")
    agent_run_parser = agent_subparsers.add_parser(
        "run",
        help="Run the constrained deterministic SIFTGuard agent workflow",
    )
    agent_run_parser.add_argument("--case-id", required=True, help="Case identifier")
    agent_run_parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Evidence manifest or synthetic parser-output manifest JSON",
    )
    agent_run_parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help=(
            "Generated agent output directory under runs/, outputs/, analysis/, "
            "or reports/generated/"
        ),
    )
    agent_run_parser.add_argument(
        "--max-iterations",
        type=int,
        required=True,
        help="Hard cap on deterministic agent phase attempts",
    )
    agent_run_parser.add_argument(
        "--max-normalized-events",
        type=int,
        help=(
            "Optional positive event cap for deterministic bounded triage on "
            "large parser outputs"
        ),
    )
    agent_run_parser.add_argument(
        "--event-selection-profile",
        choices=tuple(sorted(SUPPORTED_EVENT_SELECTION_PROFILES)),
        default="first-n",
        help=(
            "Event selection policy for bounded runs. first-n preserves legacy "
            "behavior; forensic-triage prioritizes Registry and Amcache before "
            "deterministic MFT fill."
        ),
    )
    agent_run_case_parser = agent_subparsers.add_parser(
        "run-case",
        help="Run the deterministic agent workflow from a prepared case manifest",
    )
    agent_run_case_parser.add_argument(
        "--case-id",
        help="Optional case identifier; defaults to case_id in case_prep.json",
    )
    agent_run_case_parser.add_argument(
        "--artifact-manifest",
        type=Path,
        required=True,
        help="Prepared case manifest generated by siftguard case prepare",
    )
    agent_run_case_parser.add_argument(
        "--casebook",
        type=Path,
        help="Optional JSON casebook; YAML is not supported",
    )
    agent_run_case_parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help=(
            "Generated agent output directory under runs/, outputs/, analysis/, "
            "or reports/generated/"
        ),
    )
    agent_run_case_parser.add_argument(
        "--max-iterations",
        type=int,
        required=True,
        help="Hard cap on deterministic agent phase attempts",
    )
    agent_run_case_parser.add_argument(
        "--max-normalized-events",
        type=int,
        help=(
            "Optional positive event cap for deterministic bounded triage on "
            "large parser outputs"
        ),
    )
    agent_run_case_parser.add_argument(
        "--event-selection-profile",
        choices=tuple(sorted(SUPPORTED_EVENT_SELECTION_PROFILES)),
        default="first-n",
        help=(
            "Event selection policy for bounded runs. first-n preserves legacy "
            "behavior; forensic-triage prioritizes Registry and Amcache before "
            "deterministic MFT fill."
        ),
    )
    agent_fixture_parser = agent_subparsers.add_parser(
        "run-fixture",
        help="Run the constrained agent workflow against a controlled synthetic fixture",
    )
    agent_fixture_parser.add_argument("--case-id", required=True, help="Case identifier")
    agent_fixture_parser.add_argument(
        "--fixture",
        type=Path,
        required=True,
        help="Synthetic fixture descriptor JSON",
    )
    agent_fixture_parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help=(
            "Generated agent output directory under runs/, outputs/, analysis/, "
            "or reports/generated/"
        ),
    )
    agent_fixture_parser.add_argument(
        "--max-iterations",
        type=int,
        required=True,
        help="Hard cap on deterministic agent phase attempts",
    )
    agent_fixture_parser.add_argument(
        "--max-normalized-events",
        type=int,
        help="Optional positive event cap for fixture validation runs",
    )
    agent_fixture_parser.add_argument(
        "--event-selection-profile",
        choices=tuple(sorted(SUPPORTED_EVENT_SELECTION_PROFILES)),
        default="first-n",
        help="Event selection policy for fixture validation runs.",
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

    if args.command == "case":
        if args.case_command != "prepare":
            print("error=case subcommand is required", file=sys.stderr)
            return 1

        try:
            case_result = prepare_case(
                case_id=args.case_id,
                source_root=args.source_root,
                source_manifest_path=args.source_manifest,
                source_manifest_out=args.source_manifest_out,
                output_dir=args.output_dir,
            )
        except Exception as exc:
            print(f"error={exc}", file=sys.stderr)
            return 1

        print(f"case_id={case_result.manifest.case_id}")
        print(f"status={case_result.manifest.status}")
        print(f"sources={len(case_result.manifest.sources)}")
        print(f"prepared_artifacts={len(case_result.manifest.prepared_artifacts)}")
        print(f"coverage_gaps={len(case_result.manifest.coverage_gaps)}")
        print(f"output_dir={case_result.output_dir}")
        print(f"case_prep={case_result.case_prep_path}")
        print(f"source_manifest={case_result.source_manifest_path}")
        if case_result.local_source_manifest_path is not None:
            print(f"local_source_manifest={case_result.local_source_manifest_path}")
        print(f"extraction_audit={case_result.extraction_audit_path}")
        return 0 if case_result.manifest.status != "failed" else 1

    if args.command in {"parse-mft", "parse-registry-runkeys", "parse-amcache"}:
        return _run_parser_command(args)

    if args.command == "correlate":
        try:
            correlation_result = run_correlation_workflow(
                case_id=args.case_id,
                input_path=args.input,
                output_dir=args.output_dir,
            )
        except Exception as exc:
            print(f"error={exc}", file=sys.stderr)
            return 1

        print(f"case_id={correlation_result.case_id}")
        print(f"output_dir={correlation_result.output_dir}")
        print(f"events={correlation_result.event_count}")
        print(f"timelines={correlation_result.timeline_count}")
        print(f"findings={correlation_result.finding_count}")
        print(f"timelines_path={correlation_result.timelines_path}")
        print(f"findings_path={correlation_result.findings_path}")
        print(f"report_path={correlation_result.report_path}")
        print(f"audit_path={correlation_result.audit_path}")
        return 0

    if args.command == "agent":
        if args.agent_command not in {"run", "run-case", "run-fixture"}:
            print("error=agent subcommand is required", file=sys.stderr)
            return 1

        try:
            if args.agent_command == "run-fixture":
                run = run_agent_fixture_workflow(
                    case_id=args.case_id,
                    fixture_path=args.fixture,
                    output_dir=args.output_dir,
                    max_iterations=args.max_iterations,
                    max_normalized_events=args.max_normalized_events,
                    event_selection_profile=args.event_selection_profile,
                )
            elif args.agent_command == "run-case":
                run_case_result = run_case_workflow(
                    case_id=args.case_id,
                    artifact_manifest_path=args.artifact_manifest,
                    casebook_path=args.casebook,
                    output_dir=args.output_dir,
                    max_iterations=args.max_iterations,
                    max_normalized_events=args.max_normalized_events,
                    event_selection_profile=args.event_selection_profile,
                )
                run = run_case_result.run
            else:
                run = run_agent_workflow(
                    case_id=args.case_id,
                    manifest_path=args.manifest,
                    output_dir=args.output_dir,
                    max_iterations=args.max_iterations,
                    max_normalized_events=args.max_normalized_events,
                    event_selection_profile=args.event_selection_profile,
                )
        except Exception as exc:
            print(f"error={exc}", file=sys.stderr)
            return 1

        print(f"case_id={run.case_id}")
        print(f"status={run.status.value}")
        print(f"steps={len(run.steps)}")
        if args.agent_command == "run-case":
            summary = run_case_output_summary(run_case_result)
            print(f"output_dir={summary['output_dir']}")
            print(f"agent_run={summary['agent_run']}")
            print(f"audit={summary['audit']}")
            print(f"decision_trace={summary['decision_trace']}")
            print(f"gap_analysis={summary['gap_analysis']}")
            print(f"performance_summary={summary['performance_summary']}")
        else:
            print(f"agent_run={args.output_dir.resolve() / 'agent_run.json'}")
            print(f"audit={args.output_dir.resolve() / 'audit.jsonl'}")
        return 1 if run.status is AgentRunStatus.FAILED else 0

    parser.print_help()
    return 0
