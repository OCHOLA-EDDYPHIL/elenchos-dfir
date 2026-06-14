from __future__ import annotations

import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from elenchos.case_prep.models import (
    ArtifactSidecar,
    ArtifactTarget,
    ExtractionOutcome,
    SourceRecord,
)
from elenchos.policy.paths import is_relative_to
from elenchos.runner.subprocess_runner import run_command

STATIC_TARGETS: tuple[ArtifactTarget, ...] = (
    ArtifactTarget(
        target_id="mft",
        artifact_type="mft",
        display_name="$MFT",
        output_path="extracted/mft/$MFT",
        candidate_paths=("$MFT",),
    ),
    ArtifactTarget(
        target_id="software",
        artifact_type="registry_hive",
        display_name="SOFTWARE",
        output_path="extracted/registry/SOFTWARE",
        candidate_paths=("Windows/System32/config/SOFTWARE",),
    ),
    ArtifactTarget(
        target_id="amcache",
        artifact_type="amcache_hive",
        display_name="Amcache.hve",
        output_path="extracted/amcache/Amcache.hve",
        candidate_paths=("Windows/AppCompat/Programs/Amcache.hve",),
    ),
)
NTUSER_TARGET = ArtifactTarget(
    target_id="ntuser",
    artifact_type="registry_hive",
    display_name="NTUSER.DAT",
    output_path="extracted/registry/NTUSER.DAT",
    candidate_paths=("Users/*/NTUSER.DAT",),
    registry_hive_type="ntuser",
)
SUPPORTED_TARGETS: tuple[ArtifactTarget, ...] = (*STATIC_TARGETS, NTUSER_TARGET)

_REQUIRED_EWF_TOOLS = ("ewfinfo", "ewfmount", "mmls", "fls", "icat")
_FLS_ENTRY_RE = re.compile(r"^\s*\S+(?:\s+\*)?\s+([0-9-]+):\s+(.+?)\s*$")
_AMCACHE_SIDECARS = (
    (
        "amcache_log1",
        "Amcache.hve.LOG1",
        "Windows/AppCompat/Programs/Amcache.hve.LOG1",
        "extracted/amcache/Amcache.hve.LOG1",
    ),
    (
        "amcache_log2",
        "Amcache.hve.LOG2",
        "Windows/AppCompat/Programs/Amcache.hve.LOG2",
        "extracted/amcache/Amcache.hve.LOG2",
    ),
)


@dataclass(frozen=True, slots=True)
class ExtractorContext:
    case_id: str
    source: SourceRecord
    source_path: Path
    output_dir: Path
    audit_path: Path


class CasePrepExtractor(Protocol):
    def extract(self, context: ExtractorContext) -> list[ExtractionOutcome]:
        """Extract supported artifacts for one primary source."""


def _missing_outcomes(reason: str, extraction_method: str, warning: str) -> list[ExtractionOutcome]:
    return [
        ExtractionOutcome(
            target=target,
            status="missing",
            extraction_method=extraction_method,
            reason=reason,
            warnings=[warning],
        )
        for target in SUPPORTED_TARGETS
    ]


def _safe_output_path(output_dir: Path, relative_path: str) -> Path:
    path = (output_dir / relative_path).resolve()
    if not is_relative_to(path, output_dir):
        raise ValueError(f"extraction output path escapes output_dir: {relative_path}")
    return path


class FixtureExtractor:
    """Fixture-only extractor used by unit tests."""

    def __init__(self, files_by_target_id: Mapping[str, Path]) -> None:
        self._files = {key: Path(value) for key, value in files_by_target_id.items()}

    def extract(self, context: ExtractorContext) -> list[ExtractionOutcome]:
        outcomes: list[ExtractionOutcome] = []
        for target in SUPPORTED_TARGETS:
            fixture_path = self._files.get(target.target_id)
            if fixture_path is None:
                outcomes.append(
                    ExtractionOutcome(
                        target=target,
                        status="missing",
                        extraction_method="fixture_copy",
                        reason="not_found",
                    )
                )
                continue
            output_path = _safe_output_path(context.output_dir, target.output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(fixture_path.read_bytes())
            sidecars = (
                self._copy_fixture_amcache_sidecars(context)
                if target.target_id == "amcache"
                else []
            )
            outcomes.append(
                ExtractionOutcome(
                    target=target,
                    status="available",
                    extraction_method="fixture_copy",
                    sidecars=sidecars,
                )
            )
        return outcomes

    def _copy_fixture_amcache_sidecars(
        self,
        context: ExtractorContext,
    ) -> list[ArtifactSidecar]:
        sidecars: list[ArtifactSidecar] = []
        for sidecar_id, display_name, source_ref, output_path in _AMCACHE_SIDECARS:
            fixture_path = self._files.get(sidecar_id)
            if fixture_path is None:
                sidecars.append(
                    ArtifactSidecar(
                        role="transaction_log",
                        display_name=display_name,
                        path=output_path,
                        source_candidate_ref=source_ref,
                        status="missing",
                    )
                )
                continue
            destination = _safe_output_path(context.output_dir, output_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(fixture_path.read_bytes())
            sidecars.append(
                ArtifactSidecar(
                    role="transaction_log",
                    display_name=display_name,
                    path=output_path,
                    source_candidate_ref=source_ref,
                    status="available",
                )
            )
        return sidecars


class SiftEwfExtractor:
    """EWF/Sleuth Kit extractor for local SIFT environments."""

    def extract(self, context: ExtractorContext) -> list[ExtractionOutcome]:
        if context.source.kind != "ewf_e01" or context.source.role != "disk_image":
            return _missing_outcomes(
                "unsupported_source_role",
                "unsupported_source_role",
                f"source role {context.source.role} is not supported for disk extraction",
            )

        missing_tools = [tool for tool in _REQUIRED_EWF_TOOLS if shutil.which(tool) is None]
        if missing_tools:
            return _missing_outcomes(
                "extractor_unavailable",
                "sift_ewf_tsk",
                f"missing required extractor tool(s): {', '.join(missing_tools)}",
            )

        logs_dir = context.output_dir / "_extractor_logs" / context.source.source_id
        logs_dir.mkdir(parents=True, exist_ok=True)
        work_dir = context.output_dir / "_extractor_work" / context.source.source_id
        mount_dir = work_dir / "ewfmount"
        mount_dir.mkdir(parents=True, exist_ok=True)

        ewfinfo_result = run_command(
            ["ewfinfo", str(context.source_path)],
            stdout_path=logs_dir / "ewfinfo.stdout.txt",
            stderr_path=logs_dir / "ewfinfo.stderr.txt",
            timeout_seconds=120,
            ledger_path=context.audit_path,
            case_id=context.case_id,
            tool_name="ewfinfo",
            runs_root=context.output_dir,
        )
        if ewfinfo_result.status != "success":
            return _missing_outcomes(
                "tool_error",
                "sift_ewf_tsk",
                "ewfinfo failed for disk image",
            )

        mount_result = run_command(
            ["ewfmount", str(context.source_path), str(mount_dir)],
            stdout_path=logs_dir / "ewfmount.stdout.txt",
            stderr_path=logs_dir / "ewfmount.stderr.txt",
            timeout_seconds=120,
            ledger_path=context.audit_path,
            case_id=context.case_id,
            tool_name="ewfmount",
            runs_root=context.output_dir,
        )
        if mount_result.status != "success":
            return _missing_outcomes(
                "tool_error",
                "sift_ewf_tsk",
                "ewfmount failed for disk image",
            )

        image_path = mount_dir / "ewf1"
        try:
            if not image_path.exists():
                return _missing_outcomes(
                    "tool_error",
                    "sift_ewf_tsk",
                    "ewfmount did not expose ewf1",
                )
            return self._extract_from_mounted_image(context, image_path, logs_dir)
        finally:
            self._unmount(context, mount_dir, logs_dir)

    def _extract_from_mounted_image(
        self,
        context: ExtractorContext,
        image_path: Path,
        logs_dir: Path,
    ) -> list[ExtractionOutcome]:
        offsets = self._partition_offsets(context, image_path, logs_dir)
        if not offsets:
            offsets = [0]

        last_error = "fls did not locate a readable filesystem"
        for offset in offsets:
            fls_path = logs_dir / f"fls_recursive_{offset}.txt"
            fls_result = run_command(
                ["fls", "-r", "-p", "-o", str(offset), str(image_path)],
                stdout_path=fls_path,
                stderr_path=logs_dir / f"fls_recursive_{offset}.stderr.txt",
                timeout_seconds=900,
                ledger_path=context.audit_path,
                case_id=context.case_id,
                tool_name="fls",
                runs_root=context.output_dir,
            )
            if fls_result.status != "success":
                last_error = f"fls failed for partition offset {offset}"
                continue

            entries = _parse_fls_entries(fls_path)
            matches = _target_matches(entries)
            ntuser_targets = _profile_ntuser_targets(entries)
            if not matches and not ntuser_targets:
                last_error = f"no supported artifacts found at partition offset {offset}"
                continue
            return self._extract_matches(
                context,
                image_path,
                offset,
                logs_dir,
                matches,
                ntuser_targets,
            )

        return _missing_outcomes("tool_error", "sift_ewf_tsk", last_error)

    def _partition_offsets(
        self,
        context: ExtractorContext,
        image_path: Path,
        logs_dir: Path,
    ) -> list[int]:
        mmls_path = logs_dir / "mmls.stdout.txt"
        result = run_command(
            ["mmls", str(image_path)],
            stdout_path=mmls_path,
            stderr_path=logs_dir / "mmls.stderr.txt",
            timeout_seconds=120,
            ledger_path=context.audit_path,
            case_id=context.case_id,
            tool_name="mmls",
            runs_root=context.output_dir,
        )
        if result.status != "success":
            return [0]
        text = mmls_path.read_text(encoding="utf-8", errors="replace")
        offsets: list[int] = []
        for line in text.splitlines():
            lowered = line.casefold()
            if "ntfs" not in lowered and "basic data" not in lowered:
                continue
            parts = line.split()
            numeric = [part for part in parts if part.isdigit()]
            if numeric:
                offsets.append(int(numeric[0]))
        return offsets or [0]

    def _extract_matches(
        self,
        context: ExtractorContext,
        image_path: Path,
        offset: int,
        logs_dir: Path,
        matches: Mapping[str, tuple[str, str]],
        ntuser_targets: list[tuple[ArtifactTarget, str, str]],
    ) -> list[ExtractionOutcome]:
        outcomes: list[ExtractionOutcome] = []
        for target in STATIC_TARGETS:
            match = matches.get(target.target_id)
            if match is None:
                outcomes.append(
                    ExtractionOutcome(
                        target=target,
                        status="missing",
                        extraction_method="sift_ewf_tsk",
                        reason="not_found",
                    )
                )
                continue

            inode, source_path = match
            outcome = self._extract_one_target(
                context=context,
                image_path=image_path,
                offset=offset,
                logs_dir=logs_dir,
                target=target,
                inode=inode,
                source_path=source_path,
                log_slug=f"icat_{target.target_id}",
            )
            if target.target_id == "amcache":
                outcome.sidecars = self._extract_amcache_sidecars(
                    context=context,
                    image_path=image_path,
                    offset=offset,
                    logs_dir=logs_dir,
                    matches=matches,
                )
            outcomes.append(outcome)

        if ntuser_targets:
            for target, inode, source_path in ntuser_targets:
                outcomes.append(
                    self._extract_one_target(
                        context=context,
                        image_path=image_path,
                        offset=offset,
                        logs_dir=logs_dir,
                        target=target,
                        inode=inode,
                        source_path=source_path,
                        log_slug=f"icat_{target.profile_id or target.target_id}",
                    )
                )
        else:
            outcomes.append(
                ExtractionOutcome(
                    target=NTUSER_TARGET,
                    status="missing",
                    extraction_method="sift_ewf_tsk",
                    reason="not_found",
                )
            )
        return outcomes

    def _extract_amcache_sidecars(
        self,
        *,
        context: ExtractorContext,
        image_path: Path,
        offset: int,
        logs_dir: Path,
        matches: Mapping[str, tuple[str, str]],
    ) -> list[ArtifactSidecar]:
        sidecars: list[ArtifactSidecar] = []
        for sidecar_id, display_name, source_ref, output_path in _AMCACHE_SIDECARS:
            match = matches.get(sidecar_id)
            if match is None:
                sidecars.append(
                    ArtifactSidecar(
                        role="transaction_log",
                        display_name=display_name,
                        path=output_path,
                        source_candidate_ref=source_ref,
                        status="missing",
                    )
                )
                continue

            inode, source_path = match
            destination = _safe_output_path(context.output_dir, output_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            result = run_command(
                ["icat", "-o", str(offset), str(image_path), inode],
                stdout_path=destination,
                stderr_path=logs_dir / f"icat_{sidecar_id}.stderr.txt",
                timeout_seconds=900,
                ledger_path=context.audit_path,
                case_id=context.case_id,
                tool_name="icat",
                runs_root=context.output_dir,
            )
            if result.status == "success" and destination.exists() and destination.is_file():
                status = "available"
                warnings: list[str] = []
            else:
                status = "extraction_failed"
                warnings = [f"icat failed for {display_name}"]
            sidecars.append(
                ArtifactSidecar(
                    role="transaction_log",
                    display_name=display_name,
                    path=output_path,
                    source_candidate_ref=source_ref if source_ref else source_path,
                    status=status,
                    warnings=warnings,
                )
            )
        return sidecars

    def _extract_one_target(
        self,
        *,
        context: ExtractorContext,
        image_path: Path,
        offset: int,
        logs_dir: Path,
        target: ArtifactTarget,
        inode: str,
        source_path: str,
        log_slug: str,
    ) -> ExtractionOutcome:
        destination = _safe_output_path(context.output_dir, target.output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = run_command(
            ["icat", "-o", str(offset), str(image_path), inode],
            stdout_path=destination,
            stderr_path=logs_dir / f"{log_slug}.stderr.txt",
            timeout_seconds=900,
            ledger_path=context.audit_path,
            case_id=context.case_id,
            tool_name="icat",
            runs_root=context.output_dir,
        )
        if result.status == "success" and destination.exists() and destination.is_file():
            return ExtractionOutcome(
                target=target,
                status="available",
                extraction_method=(
                    f"sift_ewf_tsk:{target.source_candidate_ref or source_path}"
                ),
            )
        return ExtractionOutcome(
            target=target,
            status="extraction_failed",
            extraction_method=(
                f"sift_ewf_tsk:{target.source_candidate_ref or source_path}"
            ),
            reason="extraction_failed",
            warnings=[f"icat failed for {target.display_name}"],
        )

    def _unmount(self, context: ExtractorContext, mount_dir: Path, logs_dir: Path) -> None:
        executable = (
            shutil.which("fusermount3")
            or shutil.which("fusermount")
            or shutil.which("umount")
        )
        if executable is None:
            return
        if "fuser" in executable:
            command = [executable, "-u", str(mount_dir)]
        else:
            command = [executable, str(mount_dir)]
        run_command(
            command,
            stdout_path=logs_dir / "unmount.stdout.txt",
            stderr_path=logs_dir / "unmount.stderr.txt",
            timeout_seconds=120,
            ledger_path=context.audit_path,
            case_id=context.case_id,
            tool_name=Path(executable).name,
            runs_root=context.output_dir,
        )


def _parse_fls_entries(fls_path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    text = fls_path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        match = _FLS_ENTRY_RE.match(line)
        if match is None:
            continue
        inode, path = match.groups()
        entries.append((inode, path.strip()))
    return entries


def _normalize_tsk_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("/").casefold()


def _target_matches(entries: list[tuple[str, str]]) -> dict[str, tuple[str, str]]:
    matches: dict[str, tuple[str, str]] = {}

    for inode, path in entries:
        normalized = _normalize_tsk_path(path)
        if normalized == "$mft" and "mft" not in matches:
            matches["mft"] = (inode, path)
        elif normalized == "windows/system32/config/software" and "software" not in matches:
            matches["software"] = (inode, path)
        elif (
            normalized == "windows/appcompat/programs/amcache.hve"
            and "amcache" not in matches
        ):
            matches["amcache"] = (inode, path)
        else:
            for sidecar_id, _display_name, source_ref, _output_path in _AMCACHE_SIDECARS:
                if normalized == _normalize_tsk_path(source_ref) and sidecar_id not in matches:
                    matches[sidecar_id] = (inode, path)

    return matches


def _profile_ntuser_source_ref(profile_id: str) -> str:
    return f"Users/{profile_id}/NTUSER.DAT"


def _ntuser_profile_candidate(path: str) -> bool:
    normalized = path.replace("\\", "/").lstrip("/")
    parts = normalized.split("/")
    if len(parts) != 3:
        return False
    return bool(parts[1]) and parts[0].casefold() == "users" and parts[2].casefold() == "ntuser.dat"


def _profile_ntuser_targets(
    entries: list[tuple[str, str]],
) -> list[tuple[ArtifactTarget, str, str]]:
    candidates = [
        (inode, path)
        for inode, path in entries
        if _ntuser_profile_candidate(path)
    ]
    targets: list[tuple[ArtifactTarget, str, str]] = []
    for index, (inode, source_path) in enumerate(
        sorted(candidates, key=lambda item: item[1].casefold()),
        start=1,
    ):
        profile_id = f"profile-{index:04d}"
        source_ref = _profile_ntuser_source_ref(profile_id)
        targets.append(
            (
                ArtifactTarget(
                    target_id=f"ntuser_{profile_id.replace('-', '_')}",
                    artifact_type="registry_hive",
                    display_name="NTUSER.DAT",
                    output_path=f"extracted/registry/profiles/{profile_id}/NTUSER.DAT",
                    candidate_paths=("Users/*/NTUSER.DAT",),
                    registry_hive_type="ntuser",
                    profile_id=profile_id,
                    profile_display_name=profile_id,
                    sanitized_profile_hint=profile_id,
                    source_candidate_ref=source_ref,
                ),
                inode,
                source_path,
            )
        )
    return targets
