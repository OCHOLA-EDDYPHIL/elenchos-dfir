from __future__ import annotations

import argparse
from pathlib import Path

from siftguard import __version__
from siftguard.audit.execution_ledger import read_events
from siftguard.evidence.hashing import sha256_file
from siftguard.evidence.manifest import build_manifest, write_manifest


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

    parser.print_help()
    return 0
