from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CASE_PREP_SCHEMA_VERSION = 1

SOURCE_ROLES = {
    "disk_image",
    "memory_image",
    "archive",
    "case_background",
}
SOURCE_KINDS = {"ewf_e01", "raw", "zip", "7z", "pptx"}
SOURCE_STATUSES = {"available", "missing", "unsupported", "staged_not_analyzed"}
SOURCE_HASH_STATUSES = {"computed", "not_requested", "failed", "skipped"}
ANALYSIS_SCOPES = {
    "primary",
    "out_of_scope_for_final_submission",
    "inventory_only",
    "case_context",
}

CASE_PREP_STATUSES = {"completed", "partial_success", "failed"}
PREPARED_ARTIFACT_TYPES = {"mft", "registry_hive", "amcache_hive"}
PREPARED_ARTIFACT_STATUSES = {"available", "missing", "skipped"}
GAP_REASONS = {
    "not_found",
    "unsupported_source_role",
    "extractor_unavailable",
    "permission_error",
    "tool_error",
}


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def stable_id(prefix: str, *parts: object, length: int = 16) -> str:
    raw = "\x1f".join(str(part) for part in parts).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:length]
    return f"{prefix}_{digest}"


def source_id_for(*, case_id: str, source_ref: str, role: str, kind: str) -> str:
    return stable_id("src", case_id, source_ref, role, kind)


def source_set_id_for(case_id: str, sources: list[SourceRecord]) -> str:
    rows = sorted(f"{source.source_ref}:{source.role}:{source.kind}" for source in sources)
    return stable_id("srcset", case_id, *rows)


def artifact_id_for(*, source_id: str, target_id: str, output_path: str) -> str:
    return stable_id("prep", source_id, target_id, output_path)


def gap_id_for(*, source_id: str, target_id: str, reason: str) -> str:
    return stable_id("gap", source_id, target_id, reason)


def _require_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _require_int(value: object, field_name: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _optional_sha256(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    digest = _require_string(value, field_name).lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"{field_name} must be a SHA256 hex digest or null")
    return digest


def _string_list(values: object, field_name: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ValueError(f"{field_name} must be a list of strings")
    return list(values)


@dataclass(slots=True)
class SourceRecord:
    source_id: str
    role: str
    kind: str
    display_name: str
    source_ref: str
    sanitized_path: str
    size_bytes: int
    sha256: str | None
    hash_status: str
    status: str
    analysis_scope: str
    local_path: str | None = None

    def __post_init__(self) -> None:
        self.source_id = _require_string(self.source_id, "source_id")
        self.role = _require_string(self.role, "role")
        if self.role not in SOURCE_ROLES:
            raise ValueError(f"invalid source role: {self.role}")
        self.kind = _require_string(self.kind, "kind")
        if self.kind not in SOURCE_KINDS:
            raise ValueError(f"invalid source kind: {self.kind}")
        self.display_name = _require_string(self.display_name, "display_name")
        self.source_ref = _require_string(self.source_ref, "source_ref")
        self.sanitized_path = _require_string(self.sanitized_path, "sanitized_path")
        self.size_bytes = _require_int(self.size_bytes, "size_bytes")
        self.sha256 = _optional_sha256(self.sha256, "sha256")
        self.hash_status = _require_string(self.hash_status, "hash_status")
        if self.hash_status not in SOURCE_HASH_STATUSES:
            raise ValueError(f"invalid source hash_status: {self.hash_status}")
        self.status = _require_string(self.status, "status")
        if self.status not in SOURCE_STATUSES:
            raise ValueError(f"invalid source status: {self.status}")
        self.analysis_scope = _require_string(self.analysis_scope, "analysis_scope")
        if self.analysis_scope not in ANALYSIS_SCOPES:
            raise ValueError(f"invalid analysis_scope: {self.analysis_scope}")
        if self.local_path is not None:
            self.local_path = _require_string(self.local_path, "local_path")

    def to_dict(self, *, include_local_paths: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "analysis_scope": self.analysis_scope,
            "display_name": self.display_name,
            "hash_status": self.hash_status,
            "kind": self.kind,
            "role": self.role,
            "sanitized_path": self.sanitized_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "source_id": self.source_id,
            "source_ref": self.source_ref,
            "status": self.status,
        }
        if include_local_paths and self.local_path is not None:
            payload["local_path"] = self.local_path
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceRecord:
        source_ref = data.get("source_ref") or data.get("sanitized_path")
        sanitized_path = data.get("sanitized_path") or source_ref
        if not isinstance(source_ref, str) or not isinstance(sanitized_path, str):
            raise ValueError("source_ref or sanitized_path must be present")
        return cls(
            source_id=_require_string(data.get("source_id"), "source_id"),
            role=_require_string(data.get("role"), "role"),
            kind=_require_string(data.get("kind"), "kind"),
            display_name=_require_string(data.get("display_name"), "display_name"),
            source_ref=source_ref,
            sanitized_path=sanitized_path,
            size_bytes=_require_int(data.get("size_bytes", 0), "size_bytes"),
            sha256=_optional_sha256(data.get("sha256"), "sha256"),
            hash_status=_require_string(data.get("hash_status"), "hash_status"),
            status=_require_string(data.get("status"), "status"),
            analysis_scope=_require_string(data.get("analysis_scope"), "analysis_scope"),
            local_path=data.get("local_path"),
        )


@dataclass(slots=True)
class SourceManifest:
    case_id: str
    source_set_id: str
    created_at: str
    sources: list[SourceRecord]
    source_root: str | None = None

    def __post_init__(self) -> None:
        self.case_id = _require_string(self.case_id, "case_id")
        self.source_set_id = _require_string(self.source_set_id, "source_set_id")
        self.created_at = _require_string(self.created_at, "created_at")
        if not self.created_at.endswith("Z"):
            raise ValueError("created_at must use UTC Z format")
        if not all(isinstance(source, SourceRecord) for source in self.sources):
            raise TypeError("sources must contain SourceRecord instances")
        if self.source_root is not None:
            self.source_root = _require_string(self.source_root, "source_root")

    def to_dict(self, *, include_local_paths: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "case_id": self.case_id,
            "created_at": self.created_at,
            "schema_version": CASE_PREP_SCHEMA_VERSION,
            "source_count": len(self.sources),
            "source_set_id": self.source_set_id,
            "sources": [
                source.to_dict(include_local_paths=include_local_paths)
                for source in sorted(self.sources, key=lambda item: item.source_ref)
            ],
        }
        if include_local_paths and self.source_root is not None:
            payload["source_root"] = self.source_root
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceManifest:
        sources_payload = data.get("sources", [])
        if not isinstance(sources_payload, list):
            raise ValueError("sources must be a list")
        sources = [SourceRecord.from_dict(dict(item)) for item in sources_payload]
        source_count = data.get("source_count")
        if source_count is not None and source_count != len(sources):
            raise ValueError("source_count does not match number of sources")
        return cls(
            case_id=_require_string(data.get("case_id"), "case_id"),
            source_set_id=_require_string(data.get("source_set_id"), "source_set_id"),
            created_at=_require_string(data.get("created_at"), "created_at"),
            sources=sources,
            source_root=data.get("source_root"),
        )


@dataclass(frozen=True, slots=True)
class ArtifactTarget:
    target_id: str
    artifact_type: str
    display_name: str
    output_path: str
    candidate_paths: tuple[str, ...]


@dataclass(slots=True)
class ExtractionOutcome:
    target: ArtifactTarget
    status: str
    extraction_method: str
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in PREPARED_ARTIFACT_STATUSES:
            raise ValueError(f"invalid extraction outcome status: {self.status}")
        if self.reason is not None and self.reason not in GAP_REASONS:
            raise ValueError(f"invalid extraction gap reason: {self.reason}")
        self.warnings = _string_list(self.warnings, "warnings")


@dataclass(slots=True)
class PreparedArtifact:
    artifact_id: str
    artifact_type: str
    source_id: str
    source_role: str
    path: str
    parser_eligible: bool
    status: str
    sha256: str | None
    hash_status: str
    extraction_method: str
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.artifact_id = _require_string(self.artifact_id, "artifact_id")
        self.artifact_type = _require_string(self.artifact_type, "artifact_type")
        if self.artifact_type not in PREPARED_ARTIFACT_TYPES:
            raise ValueError(f"invalid prepared artifact type: {self.artifact_type}")
        self.source_id = _require_string(self.source_id, "source_id")
        self.source_role = _require_string(self.source_role, "source_role")
        self.path = _require_string(self.path, "path")
        if Path(self.path).is_absolute() or ".." in Path(self.path).parts:
            raise ValueError("prepared artifact path must be relative and safe")
        if not isinstance(self.parser_eligible, bool):
            raise TypeError("parser_eligible must be a bool")
        self.status = _require_string(self.status, "status")
        if self.status not in PREPARED_ARTIFACT_STATUSES:
            raise ValueError(f"invalid prepared artifact status: {self.status}")
        self.sha256 = _optional_sha256(self.sha256, "sha256")
        self.hash_status = _require_string(self.hash_status, "hash_status")
        if self.hash_status not in SOURCE_HASH_STATUSES:
            raise ValueError(f"invalid prepared artifact hash_status: {self.hash_status}")
        self.extraction_method = _require_string(self.extraction_method, "extraction_method")
        self.warnings = _string_list(self.warnings, "warnings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "extraction_method": self.extraction_method,
            "hash_status": self.hash_status,
            "parser_eligible": self.parser_eligible,
            "path": self.path,
            "sha256": self.sha256,
            "source_id": self.source_id,
            "source_role": self.source_role,
            "status": self.status,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class CoverageGap:
    gap_id: str
    artifact_type: str
    source_id: str
    reason: str
    impact: str
    recommended_next_step: str

    def __post_init__(self) -> None:
        self.gap_id = _require_string(self.gap_id, "gap_id")
        self.artifact_type = _require_string(self.artifact_type, "artifact_type")
        if self.artifact_type not in PREPARED_ARTIFACT_TYPES:
            raise ValueError(f"invalid gap artifact_type: {self.artifact_type}")
        self.source_id = _require_string(self.source_id, "source_id")
        self.reason = _require_string(self.reason, "reason")
        if self.reason not in GAP_REASONS:
            raise ValueError(f"invalid gap reason: {self.reason}")
        self.impact = _require_string(self.impact, "impact")
        self.recommended_next_step = _require_string(
            self.recommended_next_step,
            "recommended_next_step",
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "artifact_type": self.artifact_type,
            "gap_id": self.gap_id,
            "impact": self.impact,
            "reason": self.reason,
            "recommended_next_step": self.recommended_next_step,
            "source_id": self.source_id,
        }


@dataclass(slots=True)
class CasePrepManifest:
    case_id: str
    source_set_id: str
    status: str
    sources: list[SourceRecord]
    prepared_artifacts: list[PreparedArtifact]
    coverage_gaps: list[CoverageGap]
    warnings: list[str]
    output_dir: str
    created_at: str

    def __post_init__(self) -> None:
        self.case_id = _require_string(self.case_id, "case_id")
        self.source_set_id = _require_string(self.source_set_id, "source_set_id")
        self.status = _require_string(self.status, "status")
        if self.status not in CASE_PREP_STATUSES:
            raise ValueError(f"invalid case prep status: {self.status}")
        if not all(isinstance(source, SourceRecord) for source in self.sources):
            raise TypeError("sources must contain SourceRecord instances")
        if not all(isinstance(item, PreparedArtifact) for item in self.prepared_artifacts):
            raise TypeError("prepared_artifacts must contain PreparedArtifact instances")
        if not all(isinstance(item, CoverageGap) for item in self.coverage_gaps):
            raise TypeError("coverage_gaps must contain CoverageGap instances")
        self.warnings = _string_list(self.warnings, "warnings")
        self.output_dir = _require_string(self.output_dir, "output_dir")
        self.created_at = _require_string(self.created_at, "created_at")
        if not self.created_at.endswith("Z"):
            raise ValueError("created_at must use UTC Z format")

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "coverage_gaps": [
                gap.to_dict()
                for gap in sorted(self.coverage_gaps, key=lambda item: item.gap_id)
            ],
            "created_at": self.created_at,
            "output_dir": self.output_dir,
            "prepared_artifacts": [
                artifact.to_dict()
                for artifact in sorted(self.prepared_artifacts, key=lambda item: item.artifact_id)
            ],
            "source_set_id": self.source_set_id,
            "sources": [
                source.to_dict(include_local_paths=False)
                for source in sorted(self.sources, key=lambda item: item.source_id)
            ],
            "status": self.status,
            "warnings": list(self.warnings),
        }
