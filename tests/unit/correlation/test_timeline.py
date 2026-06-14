from __future__ import annotations

import json

from elenchos.correlation.models import TimelineEvent, TimelineEventType
from elenchos.correlation.timeline import build_subject_timelines, correlate_timeline
from elenchos.validation.models import EvidenceRef

PATH_A = "C:/Users/Alice/AppData/Local/Temp/example-a.exe"
PATH_B = "C:/ProgramData/example-a.exe"
BASENAME = "example-a.exe"


def evidence_ref(
    evidence_id: str = "EV-SYN-MFT-001",
    parser: str = "mftecmd",
    source: str = "$MFT",
    raw_record_ref: str = "csv:mft.csv:1842",
) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=evidence_id,
        parser=parser,
        source=source,
        raw_record_ref=raw_record_ref,
        description="Synthetic normalized parser event reference.",
    )


def timeline_event(
    *,
    event_type: TimelineEventType = TimelineEventType.OBSERVATION,
    timestamp: str = "2026-01-01T00:00:00Z",
    source: str = "mft",
    path: str | None = PATH_A,
    basename: str | None = None,
    evidence_id: str = "EV-SYN-MFT-001",
    parser: str = "mftecmd",
    raw_record_ref: str = "csv:mft.csv:1842",
    detail: str = "synthetic observation",
) -> TimelineEvent:
    return TimelineEvent(
        event_type=event_type,
        timestamp=timestamp,
        subject=path or basename,
        source=source,
        details={"detail": detail},
        evidence_refs=[
            evidence_ref(
                evidence_id=evidence_id,
                parser=parser,
                source=source,
                raw_record_ref=raw_record_ref,
            )
        ],
        path=path,
        basename=basename,
    )


def test_empty_input_returns_empty_timelines():
    assert build_subject_timelines([]) == []


def test_timeline_event_type_supports_expected_categories_only():
    assert {event_type.value for event_type in TimelineEventType} == {
        "drop",
        "execution",
        "persistence",
        "observation",
    }


def test_same_normalized_path_groups_drop_execution_and_persistence_events():
    events = [
        timeline_event(
            event_type=TimelineEventType.DROP,
            timestamp="2026-01-01T00:00:01Z",
            path=PATH_A.replace("/", "\\"),
            detail="synthetic MFT file creation",
        ),
        timeline_event(
            event_type=TimelineEventType.EXECUTION,
            timestamp="2026-01-01T00:00:02Z",
            source="amcache",
            path=PATH_A.lower(),
            evidence_id="EV-SYN-AMCACHE-001",
            parser="amcacheparser",
            raw_record_ref="json:amcache.json:/entries/4",
            detail="synthetic Amcache execution",
        ),
        timeline_event(
            event_type=TimelineEventType.PERSISTENCE,
            timestamp="2026-01-01T00:00:03Z",
            source="registry",
            path=PATH_A,
            evidence_id="EV-SYN-REG-001",
            parser="recmd",
            raw_record_ref="json:runkeys.json:/entries/12",
            detail="synthetic Run key value",
        ),
    ]

    timelines = build_subject_timelines(events)

    assert len(timelines) == 1
    assert timelines[0].subject.casefold() == PATH_A.casefold()
    assert {event.event_type.value for event in timelines[0].events} == {
        "drop",
        "execution",
        "persistence",
    }


def test_timeline_events_sort_deterministically_by_timestamp():
    events = [
        timeline_event(timestamp="2026-01-01T00:00:03Z", detail="third"),
        timeline_event(timestamp="2026-01-01T00:00:01Z", detail="first"),
        timeline_event(timestamp="2026-01-01T00:00:02Z", detail="second"),
    ]

    timeline = build_subject_timelines(events)[0]

    assert [event.details["detail"] for event in timeline.events] == [
        "first",
        "second",
        "third",
    ]


def test_evidence_references_are_preserved_on_every_event():
    events = [
        timeline_event(event_type=TimelineEventType.DROP, evidence_id="EV-SYN-MFT-001"),
        timeline_event(
            event_type=TimelineEventType.EXECUTION,
            source="amcache",
            evidence_id="EV-SYN-AMCACHE-001",
            parser="amcacheparser",
            raw_record_ref="json:amcache.json:/entries/4",
        ),
        timeline_event(
            event_type=TimelineEventType.PERSISTENCE,
            source="registry",
            evidence_id="EV-SYN-REG-001",
            parser="recmd",
            raw_record_ref="json:runkeys.json:/entries/12",
        ),
    ]

    timeline = build_subject_timelines(events)[0]

    assert all(event.evidence_refs for event in timeline.events)
    assert [ref.evidence_id for ref in timeline.collect_evidence_refs()] == [
        "EV-SYN-MFT-001",
        "EV-SYN-AMCACHE-001",
        "EV-SYN-REG-001",
    ]


def test_missing_artifact_classes_do_not_crash():
    examples = [
        timeline_event(
            event_type=TimelineEventType.DROP,
            source="mft",
            evidence_id="EV-SYN-MFT-001",
        ),
        timeline_event(
            event_type=TimelineEventType.PERSISTENCE,
            source="registry",
            evidence_id="EV-SYN-REG-001",
            parser="recmd",
            raw_record_ref="json:runkeys.json:/entries/12",
        ),
        timeline_event(
            event_type=TimelineEventType.EXECUTION,
            source="amcache",
            evidence_id="EV-SYN-AMCACHE-001",
            parser="amcacheparser",
            raw_record_ref="json:amcache.json:/entries/4",
        ),
    ]

    for event in examples:
        timelines = build_subject_timelines([event])
        assert len(timelines) == 1
        assert timelines[0].events[0].source == event.source


def test_full_path_correlation_beats_basename_correlation():
    timelines = build_subject_timelines(
        [
            timeline_event(path=PATH_A, detail="first full path"),
            timeline_event(path=PATH_B, evidence_id="EV-SYN-MFT-002", detail="second full path"),
        ]
    )

    assert [timeline.subject for timeline in timelines] == [PATH_B, PATH_A]
    assert all(len(timeline.events) == 1 for timeline in timelines)


def test_basename_only_event_is_ambiguous_when_full_path_subjects_conflict():
    timelines = build_subject_timelines(
        [
            timeline_event(path=PATH_A, detail="first full path"),
            timeline_event(path=PATH_B, evidence_id="EV-SYN-MFT-002", detail="second full path"),
            timeline_event(
                path=None,
                basename=BASENAME,
                evidence_id="EV-SYN-AMCACHE-001",
                parser="amcacheparser",
                raw_record_ref="json:amcache.json:/entries/4",
                detail="basename only",
            ),
        ]
    )

    ambiguous = [timeline for timeline in timelines if timeline.ambiguous]

    assert len(ambiguous) == 1
    assert ambiguous[0].subject == BASENAME
    assert "multiple full-path subjects" in (ambiguous[0].ambiguity_reason or "")
    assert ambiguous[0].events[0].ambiguous is True


def test_basename_only_event_groups_with_single_full_path_subject():
    timelines = build_subject_timelines(
        [
            timeline_event(
                path=PATH_A,
                timestamp="2026-01-01T00:00:01Z",
                detail="full path",
            ),
            timeline_event(
                path=None,
                basename=BASENAME,
                timestamp="2026-01-01T00:00:02Z",
                evidence_id="EV-SYN-AMCACHE-001",
                parser="amcacheparser",
                raw_record_ref="json:amcache.json:/entries/4",
                detail="basename only",
            ),
        ]
    )

    assert len(timelines) == 1
    assert timelines[0].subject == PATH_A
    assert [event.details["detail"] for event in timelines[0].events] == [
        "full path",
        "basename only",
    ]
    assert timelines[0].ambiguous is False


def test_event_without_path_or_basename_is_preserved_as_ambiguous_unkeyed():
    event = timeline_event(
        path=None,
        basename=None,
        source="unknown",
        evidence_id="EV-SYN-UNKNOWN-001",
        parser="unknown",
        raw_record_ref="json:normalized-events.json:/entries/99",
        detail="unkeyed observation",
    )

    timelines = build_subject_timelines([event])

    assert len(timelines) == 1
    assert timelines[0].subject == "unkeyed"
    assert timelines[0].ambiguous is True
    assert timelines[0].events[0].ambiguous is True


def test_output_serialization_is_deterministic_and_json_compatible():
    events = [
        timeline_event(timestamp="2026-01-01T00:00:02Z", detail="second"),
        timeline_event(timestamp="2026-01-01T00:00:01Z", detail="first"),
    ]

    first_payload = [timeline.to_dict() for timeline in build_subject_timelines(events)]
    second_payload = [timeline.to_dict() for timeline in build_subject_timelines(reversed(events))]

    assert first_payload == second_payload
    assert json.loads(json.dumps(first_payload, sort_keys=True)) == first_payload
    assert correlate_timeline(events)[0].to_dict() == first_payload[0]


def test_synthetic_timeline_examples_contain_no_real_evidence_or_private_paths():
    payload = [
        timeline.to_dict()
        for timeline in build_subject_timelines(
            [
                timeline_event(path=PATH_A),
                timeline_event(path=PATH_B, evidence_id="EV-SYN-MFT-002"),
                timeline_event(path=None, basename=BASENAME),
            ]
        )
    ]
    encoded = json.dumps(payload)

    assert "example-a.exe" in encoded
    for forbidden in ("/mnt/evidence", "/home/", "runs/", ".local/"):
        assert forbidden not in encoded
    assert ("payload" + ".dll") not in encoded
