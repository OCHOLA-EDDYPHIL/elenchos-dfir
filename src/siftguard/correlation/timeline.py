from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from siftguard.correlation.models import SubjectTimeline, TimelineEvent


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _display_path(value: str | None) -> str | None:
    text = _clean_text(value)
    if text is None:
        return None
    normalized = text.replace("\\", "/").rstrip("/")
    return normalized or None


def _basename_from_path(value: str | None) -> str | None:
    path = _display_path(value)
    if path is None:
        return None
    return path.rsplit("/", 1)[-1] or None


def _path_key(value: str | None) -> str | None:
    path = _display_path(value)
    if path is None:
        return None
    return path.casefold()


def _basename_key(value: str | None) -> str | None:
    basename = _basename_from_path(value)
    if basename is None:
        basename = _clean_text(value)
    if basename is None:
        return None
    return basename.casefold()


def _event_path_key(event: TimelineEvent) -> str | None:
    return _path_key(event.path)


def _event_basename_key(event: TimelineEvent) -> str | None:
    if event.path:
        return _basename_key(event.path)
    return _basename_key(event.basename)


def _event_basename_display(event: TimelineEvent) -> str | None:
    if event.path:
        return _basename_from_path(event.path)
    return _clean_text(event.basename)


def _copy_with_ambiguity(event: TimelineEvent, reason: str) -> TimelineEvent:
    return TimelineEvent(
        event_type=event.event_type,
        timestamp=event.timestamp,
        subject=event.subject,
        source=event.source,
        details=dict(event.details),
        evidence_refs=list(event.evidence_refs),
        path=event.path,
        basename=event.basename,
        ambiguous=True,
        ambiguity_reason=reason,
    )


@dataclass(slots=True)
class _TimelineGroup:
    subject: str
    events: list[TimelineEvent] = field(default_factory=list)
    ambiguous: bool = False
    ambiguity_reason: str | None = None

    def add(self, event: TimelineEvent) -> None:
        self.events.append(event)
        if event.ambiguous:
            self.ambiguous = True
            if self.ambiguity_reason is None:
                self.ambiguity_reason = event.ambiguity_reason

    def to_timeline(self) -> SubjectTimeline:
        return SubjectTimeline(
            subject=self.subject,
            events=list(self.events),
            ambiguous=self.ambiguous,
            ambiguity_reason=self.ambiguity_reason,
        )


def _timeline_sort_key(timeline: SubjectTimeline) -> tuple[bool, str, str]:
    return (
        timeline.ambiguous,
        timeline.subject.casefold(),
        timeline.ambiguity_reason or "",
    )


def _require_timeline_events(events: Sequence[TimelineEvent]) -> list[TimelineEvent]:
    event_list = list(events)
    if not all(isinstance(event, TimelineEvent) for event in event_list):
        raise TypeError("events must contain only TimelineEvent instances")
    return event_list


def build_subject_timelines(events: Sequence[TimelineEvent]) -> list[SubjectTimeline]:
    event_list = _require_timeline_events(events)
    if not event_list:
        return []

    path_displays: dict[str, set[str]] = {}
    basename_to_paths: dict[str, set[str]] = {}
    for event in event_list:
        path_key = _event_path_key(event)
        basename_key = _event_basename_key(event)
        if path_key is None:
            continue
        display = _display_path(event.path)
        path_displays.setdefault(path_key, set()).add(display or path_key)
        if basename_key is not None:
            basename_to_paths.setdefault(basename_key, set()).add(path_key)

    path_subjects = {
        path_key: sorted(displays, key=lambda value: (value.casefold(), value))[0]
        for path_key, displays in path_displays.items()
    }

    groups: dict[str, _TimelineGroup] = {}
    for event in event_list:
        path_key = _event_path_key(event)
        basename_key = _event_basename_key(event)

        if path_key is not None:
            group_key = f"path:{path_key}"
            subject = path_subjects[path_key]
            groups.setdefault(group_key, _TimelineGroup(subject=subject)).add(event)
            continue

        if basename_key is not None:
            matching_paths = basename_to_paths.get(basename_key, set())
            basename = _event_basename_display(event) or basename_key
            if len(matching_paths) == 1:
                matched_path = next(iter(matching_paths))
                group_key = f"path:{matched_path}"
                subject = path_subjects[matched_path]
                groups.setdefault(group_key, _TimelineGroup(subject=subject)).add(event)
                continue
            if len(matching_paths) > 1:
                conflicting_subjects = sorted(
                    path_subjects[path_key] for path_key in matching_paths
                )
                reason = (
                    "basename matches multiple full-path subjects: "
                    + ", ".join(conflicting_subjects)
                )
                group_key = f"ambiguous-basename:{basename_key}"
                group = groups.setdefault(
                    group_key,
                    _TimelineGroup(
                        subject=basename,
                        ambiguous=True,
                        ambiguity_reason=reason,
                    ),
                )
                group.add(_copy_with_ambiguity(event, reason))
                continue

            group_key = f"basename:{basename_key}"
            groups.setdefault(group_key, _TimelineGroup(subject=basename)).add(event)
            continue

        reason = "event has no path or basename"
        group = groups.setdefault(
            "unkeyed",
            _TimelineGroup(
                subject="unkeyed",
                ambiguous=True,
                ambiguity_reason=reason,
            ),
        )
        group.add(_copy_with_ambiguity(event, reason))

    return sorted(
        (group.to_timeline() for group in groups.values()),
        key=_timeline_sort_key,
    )


def correlate_timeline(events: Sequence[TimelineEvent]) -> list[SubjectTimeline]:
    return build_subject_timelines(events)
