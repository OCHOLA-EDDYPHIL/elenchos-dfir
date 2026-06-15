from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from elenchos.agent.case_manifest_adapter import (
    AGENT_ARTIFACT_TYPE_BY_PREP_TYPE,
    adapt_case_prep_to_evidence_manifest,
    load_case_prep_manifest,
)
from elenchos.integrations.rationale_trace import run_job_path, safe_read_json
from elenchos.integrations.safe_paths import display_path, resolve_user_path

FORBIDDEN_PREPARED_MANIFEST_NAMES = {
    "model_rationale.jsonl",
    "orchestration_trace.json",
    "policy_decisions.jsonl",
    "run_integrity_manifest.json",
    "validation_summary.json",
}


@dataclass(frozen=True, slots=True)
class PreparedManifestValidation:
    path: Path
    case_id: str
    supported_artifact_count: int
    prepared_artifact_count: int
    readable_artifact_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": display_path(self.path),
            "case_id": self.case_id,
            "supported_artifact_count": self.supported_artifact_count,
            "prepared_artifact_count": self.prepared_artifact_count,
            "readable_artifact_count": self.readable_artifact_count,
        }


def _resolve_candidate(path_text: str, field_name: str) -> Path:
    path = resolve_user_path(path_text, field_name)
    _reject_known_wrong_manifest(path)
    return path


def _reject_known_wrong_manifest(path: Path) -> None:
    if path.name in FORBIDDEN_PREPARED_MANIFEST_NAMES:
        raise ValueError(
            "prepared_manifest_path points to "
            f"{path.name}, not a prepared case manifest"
        )
    if path.suffix != ".json":
        raise ValueError("prepared_manifest_path must point to case_prep.json")


def _candidate_paths(output_dir: Path) -> list[Path]:
    resolved = output_dir.resolve()
    candidates = [
        resolved / "case_prep.json",
        resolved / "prep" / "case_prep.json",
        resolved / "case-prep" / "case_prep.json",
        resolved.parent / "prep" / "case_prep.json",
        resolved.parent / "case-prep" / "case_prep.json",
    ]
    trace_candidates = [
        resolved / "openclaw-trace" / "prepare_case.stdout",
        resolved / "prep" / "openclaw-trace" / "prepare_case.stdout",
        resolved / "case-prep" / "openclaw-trace" / "prepare_case.stdout",
        resolved.parent / "prep" / "openclaw-trace" / "prepare_case.stdout",
        resolved.parent / "case-prep" / "openclaw-trace" / "prepare_case.stdout",
    ]
    for trace_path in trace_candidates:
        candidates.extend(_case_prep_paths_from_prepare_stdout(trace_path))
    return _dedupe_paths(candidates)


def _case_prep_paths_from_prepare_stdout(trace_path: Path) -> list[Path]:
    if not trace_path.is_file():
        return []
    paths: list[Path] = []
    for line in trace_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.startswith("case_prep="):
            continue
        raw_path = line.split("=", 1)[1].strip()
        if not raw_path:
            continue
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = (trace_path.parent.parent / candidate).resolve()
        paths.append(candidate.resolve())
    return paths


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    output: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        key = resolved.as_posix()
        if key in seen:
            continue
        seen.add(key)
        output.append(resolved)
    return output


def resolve_prepared_manifest_path(
    *,
    output_dir: Path,
    explicit_path: str | None = None,
) -> Path:
    if explicit_path:
        return _resolve_candidate(explicit_path, "prepared_manifest_path")

    job = safe_read_json(run_job_path(output_dir))
    if job is not None:
        value = job.get("prepared_manifest_path") or job.get("artifact_manifest")
        if isinstance(value, str) and value:
            try:
                path = _resolve_candidate(value, "prepared_manifest_path")
            except ValueError:
                path = None
            if isinstance(path, Path) and path.is_file():
                return path

    for candidate in _candidate_paths(output_dir):
        if candidate.name != "case_prep.json":
            continue
        if candidate.is_file():
            return candidate.resolve()

    raise ValueError(
        "No valid prepared manifest found. Run prepare_case first or pass "
        "prepared_manifest_path."
    )


def validate_prepared_manifest_for_run(manifest_path: Path) -> PreparedManifestValidation:
    resolved = manifest_path.resolve()
    _reject_known_wrong_manifest(resolved)
    if resolved.name != "case_prep.json":
        raise ValueError(
            "prepared_manifest_path must point to an Elenchos case_prep.json"
        )
    payload = load_case_prep_manifest(resolved)
    prepared_artifacts_raw = payload.get("prepared_artifacts")
    prepared_artifacts = (
        prepared_artifacts_raw
        if isinstance(prepared_artifacts_raw, list)
        else []
    )
    adapted = adapt_case_prep_to_evidence_manifest(
        case_prep_path=resolved,
        requested_case_id=None,
    )
    supported_artifacts = [
        artifact
        for artifact in prepared_artifacts
        if isinstance(artifact, dict)
        and artifact.get("status") == "available"
        and artifact.get("parser_eligible") is True
        and artifact.get("artifact_type") in AGENT_ARTIFACT_TYPE_BY_PREP_TYPE
    ]
    if not supported_artifacts:
        raise ValueError(
            "prepared_manifest_path contains no supported prepared artifacts for run_case"
        )
    readable_count = 0
    missing_paths: list[str] = []
    for artifact in supported_artifacts:
        relative_path = artifact.get("path")
        if not isinstance(relative_path, str) or not relative_path:
            missing_paths.append(str(artifact.get("artifact_id", "<unknown>")))
            continue
        artifact_path = (resolved.parent / relative_path).resolve()
        if artifact_path.is_file():
            readable_count += 1
        else:
            missing_paths.append(relative_path)
    if missing_paths:
        preview = ", ".join(missing_paths[:3])
        raise ValueError(
            "prepared_manifest_path references unreadable prepared artifact(s): "
            f"{preview}"
        )
    return PreparedManifestValidation(
        path=resolved,
        case_id=adapted.case_id,
        supported_artifact_count=len(supported_artifacts),
        prepared_artifact_count=len(prepared_artifacts),
        readable_artifact_count=readable_count,
    )


def prepared_manifest_details(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    validation = validate_prepared_manifest_for_run(path)
    return validation.to_dict()
