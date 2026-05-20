from __future__ import annotations

import hashlib
import json
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
    discovered_at_utc: str | None = None


@dataclass(slots=True)
class EvidenceManifest:
    case_dir: str
    generated_at_utc: str
    artifacts: list[EvidenceArtifact]


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def artifact_id_for(relative_path: str, sha256: str) -> str:
    raw = f"{relative_path}\0{sha256}".encode("utf-8")
    return f"art_{hashlib.sha256(raw).hexdigest()[:16]}"


def write_manifest(manifest: EvidenceManifest, path: Path) -> None:
    payload = {
        "case_dir": manifest.case_dir,
        "generated_at_utc": manifest.generated_at_utc,
        "artifacts": [asdict(artifact) for artifact in manifest.artifacts],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def read_manifest(path: Path) -> EvidenceManifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    artifacts = [EvidenceArtifact(**item) for item in data.get("artifacts", [])]
    return EvidenceManifest(
        case_dir=data["case_dir"],
        generated_at_utc=data["generated_at_utc"],
        artifacts=artifacts,
    )


def build_manifest(case_dir: Path, output_path: Path | None = None) -> EvidenceManifest:
    from siftguard.evidence.inventory import inventory_case

    resolved_case_dir = case_dir.resolve()
    artifacts = inventory_case(resolved_case_dir)
    manifest = EvidenceManifest(
        case_dir=str(resolved_case_dir),
        generated_at_utc=utc_now_z(),
        artifacts=artifacts,
    )
    if output_path is not None:
        write_manifest(manifest, output_path)
    return manifest
