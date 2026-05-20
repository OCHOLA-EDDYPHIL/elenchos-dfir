from __future__ import annotations

from pathlib import Path

from siftguard.evidence.hashing import sha256_file
from siftguard.evidence.manifest import (
    EvidenceArtifact,
    artifact_id_for,
    utc_now_z,
)

REGISTRY_HIVE_NAMES = {
    "software",
    "system",
    "sam",
    "security",
    "ntuser.dat",
    "usrclass.dat",
}


DISK_IMAGE_EXTENSIONS = {
    ".e01",
    ".ex01",
    ".raw",
    ".img",
    ".dd",
    ".vmdk",
    ".qcow2",
    ".vhd",
    ".vhdx",
}


MEMORY_IMAGE_EXTENSIONS = {".mem", ".vmem", ".dmp"}


def classify_artifact(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()

    if name in {"$mft", "mft"}:
        return "mft"
    if name == "amcache.hve":
        return "amcache"
    if name in REGISTRY_HIVE_NAMES:
        return "registry_hive"
    if suffix == ".evtx":
        return "evtx"
    if suffix in MEMORY_IMAGE_EXTENSIONS:
        return "memory_image"
    if suffix in DISK_IMAGE_EXTENSIONS:
        return "disk_image"
    return "unknown"


def inventory_case(case_dir: Path) -> list[EvidenceArtifact]:
    artifacts: list[EvidenceArtifact] = []
    root = case_dir.resolve()

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        rel = path.relative_to(root).as_posix()
        digest = sha256_file(path)
        artifact_type = classify_artifact(path)
        artifacts.append(
            EvidenceArtifact(
                artifact_id=artifact_id_for(rel, digest),
                path=str(path.resolve()),
                relative_path=rel,
                size_bytes=path.stat().st_size,
                sha256=digest,
                artifact_type=artifact_type,
                discovered_at_utc=utc_now_z(),
            )
        )

    return artifacts
