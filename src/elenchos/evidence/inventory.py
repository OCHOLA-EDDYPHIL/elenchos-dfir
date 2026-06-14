from __future__ import annotations

from pathlib import Path

from elenchos.evidence.hashing import sha256_file
from elenchos.evidence.manifest import (
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

DISK_IMAGE_EXTENSIONS = {".e01", ".ex01", ".dd", ".raw", ".img"}
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
    if suffix in DISK_IMAGE_EXTENSIONS:
        return "disk_image"
    if suffix in MEMORY_IMAGE_EXTENSIONS:
        return "memory_image"
    return "unknown"


def inventory_case(case_dir: Path) -> list[EvidenceArtifact]:
    if not case_dir.exists():
        raise FileNotFoundError(case_dir)
    if not case_dir.is_dir():
        raise NotADirectoryError(case_dir)

    root = case_dir.resolve()
    artifacts: list[EvidenceArtifact] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        relative_path = path.relative_to(root).as_posix()
        sha256 = sha256_file(path)
        artifacts.append(
            EvidenceArtifact(
                artifact_id=artifact_id_for(relative_path, sha256),
                path=str(path.resolve()),
                relative_path=relative_path,
                size_bytes=path.stat().st_size,
                sha256=sha256,
                artifact_type=classify_artifact(path),
                discovered_at_utc=utc_now_z(),
            )
        )

    return sorted(artifacts, key=lambda item: item.relative_path)
