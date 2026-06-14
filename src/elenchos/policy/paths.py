from __future__ import annotations

from pathlib import Path

GENERATED_OUTPUT_PARTS = {"runs", "outputs", "analysis"}
MOUNTED_EVIDENCE_ROOT = Path("/mnt/evidence")


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


def is_generated_output_path(path: Path) -> bool:
    parts = tuple(part.casefold() for part in path.resolve().parts)
    if any(part in GENERATED_OUTPUT_PARTS for part in parts):
        return True
    return any(
        left == "reports" and right == "generated"
        for left, right in zip(parts, parts[1:], strict=False)
    )


def generated_output_display_path(path: Path) -> str:
    resolved = path.resolve()
    parts = tuple(resolved.parts)
    lowered = tuple(part.casefold() for part in parts)

    for index, part in enumerate(lowered):
        if part in GENERATED_OUTPUT_PARTS:
            return Path(*parts[index:]).as_posix()
        if (
            part == "reports"
            and index + 1 < len(lowered)
            and lowered[index + 1] == "generated"
        ):
            return Path(*parts[index:]).as_posix()
    return resolved.name


def validate_generated_output_dir(
    output_dir: Path,
    *,
    forbidden_roots: list[Path] | tuple[Path, ...] = (),
    evidence_root: Path = MOUNTED_EVIDENCE_ROOT,
) -> Path:
    resolved = output_dir.resolve()
    cwd = Path.cwd().resolve()

    if resolved == cwd:
        raise ValueError("output_dir must not be the repository root")
    if is_relative_to(resolved, evidence_root):
        raise ValueError(f"output_dir must not be under evidence root '{evidence_root}'")
    for root in forbidden_roots:
        resolved_root = root.resolve()
        if is_relative_to(resolved, resolved_root):
            raise ValueError(f"output_dir must not be inside source root '{resolved_root}'")
    if not is_generated_output_path(resolved):
        raise ValueError(
            "output_dir must be under an ignored generated output path such as "
            "runs/, outputs/, analysis/, or reports/generated/"
        )
    return resolved
