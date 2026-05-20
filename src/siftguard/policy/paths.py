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
        raise ValueError(
            f"path traversal detected: '{candidate}' resolves outside base '{resolved_base}'"
        )
    return resolved_candidate


def assert_not_inside_evidence_output(output_path: Path, evidence_root: Path) -> None:
    if is_relative_to(output_path.resolve(), evidence_root.resolve()):
        raise ValueError(
            "output path "
            f"'{output_path}' is inside evidence root '{evidence_root}', which is forbidden"
        )


def assert_output_under_runs(output_path: Path, runs_root: Path) -> None:
    if not is_relative_to(output_path.resolve(), runs_root.resolve()):
        raise ValueError(
            f"output path '{output_path}' must be inside runs root '{runs_root}'"
        )


def validate_output_path(
    output_path: Path,
    runs_root: Path,
    evidence_root: Path | None = None,
) -> Path:
    if evidence_root is not None and output_path.is_absolute():
        assert_not_inside_evidence_output(output_path, evidence_root)

    resolved_output = resolve_under(runs_root, output_path)
    assert_output_under_runs(resolved_output, runs_root)

    if evidence_root is not None:
        assert_not_inside_evidence_output(resolved_output, evidence_root)

    return resolved_output
