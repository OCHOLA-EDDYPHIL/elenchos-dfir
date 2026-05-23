from __future__ import annotations

from pathlib import Path

from siftguard.policy.paths import assert_not_inside_evidence_output, is_relative_to

FORBIDDEN_IDENTIFIER_CHARS = {
    "/",
    "\\",
    "\x00",
    "\n",
    "\r",
    ";",
    "&",
    "|",
    ">",
    "<",
    "`",
    "$",
}


def validate_parser_path_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be a non-empty identifier")
    if value in {".", ".."} or ".." in value:
        raise ValueError(f"{field_name} must not contain traversal")
    if Path(value).is_absolute():
        raise ValueError(f"{field_name} must not be absolute")
    for forbidden in FORBIDDEN_IDENTIFIER_CHARS:
        if forbidden in value:
            raise ValueError(f"{field_name} contains a forbidden character")
    return value


def _validate_under_runs(path: Path, runs_root: Path) -> Path:
    resolved_runs_root = runs_root.resolve()
    resolved_path = path.resolve()
    if not is_relative_to(resolved_path, resolved_runs_root):
        raise ValueError(
            f"parser output path '{resolved_path}' must be under '{resolved_runs_root}'"
        )
    return resolved_path


def build_parser_output_dir(
    runs_root: Path,
    case_id: str,
    artifact_id: str,
    parser_name: str,
    evidence_root: Path | None = None,
) -> Path:
    safe_case_id = validate_parser_path_identifier(case_id, "case_id")
    safe_artifact_id = validate_parser_path_identifier(artifact_id, "artifact_id")
    safe_parser_name = validate_parser_path_identifier(parser_name, "parser_name")

    path = (
        runs_root
        / safe_case_id
        / "parser_outputs"
        / safe_artifact_id
        / safe_parser_name
    )
    resolved_path = _validate_under_runs(path, runs_root)
    if evidence_root is not None:
        assert_not_inside_evidence_output(resolved_path, evidence_root)
    return resolved_path


def ensure_parser_output_dir(
    runs_root: Path,
    case_id: str,
    artifact_id: str,
    parser_name: str,
    evidence_root: Path | None = None,
) -> Path:
    output_dir = build_parser_output_dir(
        runs_root,
        case_id,
        artifact_id,
        parser_name,
        evidence_root,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def build_parser_logs_dir(
    runs_root: Path,
    case_id: str,
    evidence_root: Path | None = None,
) -> Path:
    safe_case_id = validate_parser_path_identifier(case_id, "case_id")
    path = runs_root / safe_case_id / "logs"
    resolved_path = _validate_under_runs(path, runs_root)
    if evidence_root is not None:
        assert_not_inside_evidence_output(resolved_path, evidence_root)
    return resolved_path


def build_parser_normalized_dir(
    runs_root: Path,
    case_id: str,
    evidence_root: Path | None = None,
) -> Path:
    safe_case_id = validate_parser_path_identifier(case_id, "case_id")
    path = runs_root / safe_case_id / "normalized"
    resolved_path = _validate_under_runs(path, runs_root)
    if evidence_root is not None:
        assert_not_inside_evidence_output(resolved_path, evidence_root)
    return resolved_path
