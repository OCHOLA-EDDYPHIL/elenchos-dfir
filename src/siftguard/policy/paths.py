from __future__ import annotations

from pathlib import Path


def is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def resolve_under(base: Path, candidate: Path) -> Path:
    resolved_base = base.resolve()
    if candidate.is_absolute():
        resolved_candidate = candidate.resolve()
    else:
        resolved_candidate = (resolved_base / candidate).resolve()
    if not is_relative_to(resolved_candidate, resolved_base):
        raise ValueError(f"path escapes base directory: {candidate}")
    return resolved_candidate


def assert_not_inside_evidence_output(output_path: Path, evidence_root: Path) -> None:
    if is_relative_to(output_path.resolve(), evidence_root.resolve()):
        raise ValueError("output_path must not be inside evidence root")


def assert_output_under_runs(output_path: Path, runs_root: Path) -> None:
    if not is_relative_to(output_path.resolve(), runs_root.resolve()):
        raise ValueError("output_path must be under runs root")
