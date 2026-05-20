from __future__ import annotations

import argparse
from pathlib import Path

from siftguard import __version__
from siftguard.evidence.hashing import sha256_file
from siftguard.evidence.manifest import build_manifest


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
        default=None,
        help="Write manifest JSON to this path",
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
        manifest = build_manifest(args.case_dir, output_path=args.manifest_out)
        if args.manifest_out is None:
            print(f"artifacts={len(manifest.artifacts)}")
        else:
            print(f"wrote manifest: {args.manifest_out}")
        return 0

    parser.print_help()
    return 0
