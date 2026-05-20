from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class EvidenceArtifact:
    artifact_id: str
    path: str
    relative_path: str
    size_bytes: int
    sha256: str
    artifact_type: str
    discovered_at_utc: str


@dataclass(slots=True)
class EvidenceManifest:
    case_id: str
    generated_at_utc: str
    case_root: str
    artifact_count: int
    artifacts: list[EvidenceArtifact]


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def artifact_id_for(relative_path: str, sha256: str) -> str:
    raw = f"{relative_path}:{sha256}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:16]
    return f"artifact_{digest}"


def _default_case_id(case_root: Path) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", case_root.name).strip("_").lower()
    if not slug:
        slug = "default"
    return f"case_{slug}"


def write_manifest(manifest: EvidenceManifest, path: Path) -> None:
    ordered_artifacts = sorted(manifest.artifacts, key=lambda item: item.relative_path)
    payload = {
        "case_id": manifest.case_id,
        "generated_at_utc": manifest.generated_at_utc,
        "case_root": manifest.case_root,
        "artifact_count": len(ordered_artifacts),
        "artifacts": [asdict(artifact) for artifact in ordered_artifacts],
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def read_manifest(path: Path) -> EvidenceManifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    artifacts = [EvidenceArtifact(**item) for item in data.get("artifacts", [])]
    if data.get("artifact_count") != len(artifacts):
        raise ValueError("manifest artifact_count does not match number of artifacts")

    return EvidenceManifest(
        case_id=data["case_id"],
        generated_at_utc=data["generated_at_utc"],
        case_root=data["case_root"],
        artifact_count=data["artifact_count"],
        artifacts=artifacts,
    )


def build_manifest(case_dir: Path, case_id: str | None = None) -> EvidenceManifest:
    from siftguard.evidence.inventory import inventory_case

    resolved_case_dir = case_dir.resolve()
    artifacts = sorted(inventory_case(resolved_case_dir), key=lambda item: item.relative_path)
    resolved_case_id = case_id or _default_case_id(resolved_case_dir)

    return EvidenceManifest(
        case_id=resolved_case_id,
        generated_at_utc=utc_now_z(),
        case_root=str(resolved_case_dir),
        artifact_count=len(artifacts),
        artifacts=artifacts,
    )
