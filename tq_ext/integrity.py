"""Cross-source log integrity checks.

Each check compares independent records of the same activity. A log cleaner
that edits one file rarely edits the others consistently, so disagreement is
the signal. Every check states what it compared and when it cannot judge, and
prefers staying silent over guessing.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime
from itertools import pairwise
from statistics import median
from typing import Any

from uac_parser.timeline.event import TimelineEvent

LOGIN_MATCH_SECONDS = 120
AUTH_MATCH_SECONDS = 300
GAP_SOURCE_TYPES = {"syslog", "journal_text", "journal_binary", "auditd"}
GAP_MIN_EVENTS = 200
GAP_MIN_SECONDS = 2 * 3600
GAP_MEDIAN_FACTOR = 50
GAP_BOOT_SLACK_SECONDS = 600
GAP_ACTIVITY_MIN_EVENTS = 3
MAX_GAPS_PER_SOURCE = 5
MAX_FINDINGS_PER_CHECK = 100
AUTH_PROCESSES = {
    "sshd",
    "login",
    "systemd-logind",
    "su",
    "sudo",
    "gdm",
    "sddm",
    "lightdm",
}
BOOT_MARKERS = (
    "linux version ",
    "booting linux",
    "kernel command line",
    "command line: boot_image",
)
SYSTEMATIC_MISMATCH_MIN = 3
SYSTEMATIC_MISMATCH_RATIO = 0.5


def _epoch(event: TimelineEvent) -> float | None:
    if not event.timestamp:
        return None
    try:
        return datetime.fromisoformat(
            event.timestamp.replace("Z", "+00:00")
        ).timestamp()
    except ValueError:
        return None


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(int(epoch), UTC).isoformat().replace("+00:00", "Z")


def _duration(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 120:
        return f"{minutes} min"
    hours = minutes / 60
    return f"{hours:.1f} h" if hours < 48 else f"{hours / 24:.1f} days"


def _finding(
    *,
    host: str,
    epoch: float | None,
    action: str,
    severity: str,
    confidence: str,
    summary: str,
    sources: Sequence[str],
    mitre: Sequence[str] = ("T1070.002",),
    user: str | None = None,
    src_ip: str | None = None,
    extra: dict[str, Any] | None = None,
) -> TimelineEvent:
    return TimelineEvent(
        timestamp=_iso(epoch) if epoch is not None else "",
        timestamp_raw=str(int(epoch)) if epoch is not None else "",
        timezone="UTC",
        timezone_confidence="source_epoch" if epoch is not None else "missing",
        timestamp_type="inferred_from_compared_records"
        if epoch is not None
        else "unknown",
        evidence_role="inference",
        host=host,
        source_path=" vs ".join(dict.fromkeys(sources)),
        source_type="integrity_check",
        parser="tq_ext.integrity",
        event_category="defense_evasion",
        event_action=action,
        user=user,
        src_ip=src_ip,
        severity=severity,
        confidence=confidence,
        tags=["log_integrity", "cross_source_check"],
        detection_names=[action],
        ttp_flags=[action],
        mitre=list(mitre),
        summary=summary,
        raw=summary,
        extra=extra or {},
    )


def _is_wtmp(event: TimelineEvent) -> bool:
    return event.source_type == "login_binary" and "wtmp" in event.tags


def _nearby(sorted_epochs: list[float], epoch: float, window: float) -> bool:
    index = bisect_left(sorted_epochs, epoch - window)
    return index < len(sorted_epochs) and sorted_epochs[index] <= epoch + window


def check_lastlog_against_wtmp(
    events: Sequence[TimelineEvent], sources: Sequence[Any], host: str
) -> list[TimelineEvent]:
    """A lastlog entry should have a matching wtmp login record."""
    lastlog = [e for e in events if e.event_action == "last_login_record" and _epoch(e)]
    if not lastlog:
        return []
    wtmp_sources = [
        s
        for s in sources
        if getattr(s, "source_type", "") == "login_binary"
        and str(getattr(s, "relative", "")).rsplit("/", 1)[-1].startswith("wtmp")
    ]
    wtmp_events = [e for e in events if _is_wtmp(e) and _epoch(e)]
    lastlog_path = lastlog[0].source_path
    if not wtmp_events:
        if not wtmp_sources:
            return []
        newest = max(lastlog, key=lambda e: _epoch(e) or 0)
        return [
            _finding(
                host=host,
                epoch=_epoch(newest),
                action="wtmp_empty_with_lastlog_records",
                severity="medium",
                confidence="low",
                summary=(
                    f"lastlog holds {len(lastlog)} login record(s), the newest at "
                    f"{newest.timestamp}, but the collected wtmp holds no records. "
                    "wtmp was emptied, or it was rotated and the rotated file was not collected."
                ),
                sources=[lastlog_path, *(str(s.relative) for s in wtmp_sources)],
                extra={"lastlog_records": len(lastlog)},
            )
        ]
    coverage_start = min(_epoch(e) or 0 for e in wtmp_events)
    logins = [e for e in wtmp_events if e.event_action == "login_session"]
    by_user: dict[str, list[float]] = defaultdict(list)
    by_tty: dict[str, list[float]] = defaultdict(list)
    for login in logins:
        moment = _epoch(login) or 0
        if login.user:
            by_user[login.user].append(moment)
        by_tty[str(login.extra.get("tty") or "")].append(moment)
    for values in (*by_user.values(), *by_tty.values()):
        values.sort()
    wtmp_path = wtmp_events[0].source_path
    findings = []
    for record in lastlog:
        moment = _epoch(record) or 0
        if moment < coverage_start:
            continue  # Older than the collected wtmp history: cannot judge.
        candidates = (
            by_user.get(record.user, [])
            if record.user
            else by_tty.get(str(record.extra.get("tty") or ""), [])
        )
        if _nearby(candidates, moment, LOGIN_MATCH_SECONDS):
            continue
        who = record.user or f"uid {record.uid}"
        origin = record.src_ip or str(record.extra.get("remote_host") or "local")
        findings.append(
            _finding(
                host=host,
                epoch=moment,
                action="lastlog_login_missing_from_wtmp",
                severity="high",
                confidence="medium",
                summary=(
                    f"lastlog records a login for {who} from {origin} at {record.timestamp}, "
                    "but wtmp has no login record for that account within "
                    f"{LOGIN_MATCH_SECONDS} seconds even though wtmp covers that time. "
                    "The wtmp record was likely removed."
                ),
                sources=[lastlog_path, wtmp_path],
                user=record.user,
                src_ip=record.src_ip,
                extra={
                    "uid": record.uid,
                    "wtmp_coverage_start": _iso(coverage_start),
                    "compared_event": record.raw,
                },
            )
        )
    return findings[:MAX_FINDINGS_PER_CHECK]


def _is_auth_record(event: TimelineEvent) -> bool:
    if event.source_type == "auth_log":
        return True
    process = (event.process or "").rsplit("/", 1)[-1]
    return (
        event.source_type in {"journal_text", "journal_binary"}
        and process in AUTH_PROCESSES
    )


def check_wtmp_against_auth_log(
    events: Sequence[TimelineEvent], sources: Sequence[Any], host: str
) -> list[TimelineEvent]:
    """A remote wtmp login should have authentication log entries around it."""
    auth = sorted(m for e in events if _is_auth_record(e) and (m := _epoch(e)))
    logins = [
        e
        for e in events
        if _is_wtmp(e) and e.event_action == "login_session" and e.src_ip and _epoch(e)
    ]
    if not auth or not logins:
        return []
    auth_paths = list(
        dict.fromkeys(e.source_path for e in events if _is_auth_record(e))
    )[:3]
    judged = [e for e in logins if auth[0] <= (_epoch(e) or 0) <= auth[-1]]
    missing = [
        e for e in judged if not _nearby(auth, _epoch(e) or 0, AUTH_MATCH_SECONDS)
    ]
    if not missing:
        return []
    if (
        len(missing) >= SYSTEMATIC_MISMATCH_MIN
        and len(missing) / len(judged) > SYSTEMATIC_MISMATCH_RATIO
    ):
        return [
            _finding(
                host=host,
                epoch=_epoch(missing[0]),
                action="wtmp_and_auth_log_disagree_systematically",
                severity="low",
                confidence="low",
                summary=(
                    f"{len(missing)} of {len(judged)} wtmp logins have no authentication log "
                    f"entry within {AUTH_MATCH_SECONDS} seconds. A mismatch this broad usually "
                    "means the timezone chosen for text logs is wrong, or the authentication "
                    "log was heavily edited. Check the timezone setting before relying on it."
                ),
                sources=[missing[0].source_path, *auth_paths],
                mitre=(),
                extra={"unmatched_logins": len(missing), "judged_logins": len(judged)},
            )
        ]
    return [
        _finding(
            host=host,
            epoch=_epoch(login),
            action="wtmp_login_missing_from_auth_log",
            severity="high",
            confidence="medium",
            summary=(
                f"wtmp records a login for {login.user} from {login.src_ip} at "
                f"{login.timestamp}, but the authentication log has no entry within "
                f"{AUTH_MATCH_SECONDS} seconds even though it covers that time. "
                "The authentication log entries were likely removed."
            ),
            sources=[login.source_path, *auth_paths],
            user=login.user,
            src_ip=login.src_ip,
            extra={"compared_event": login.raw},
        )
        for login in missing[:MAX_FINDINGS_PER_CHECK]
    ]


def _boot_times(events: Sequence[TimelineEvent]) -> list[float]:
    boots = []
    for event in events:
        moment = _epoch(event)
        if moment is None:
            continue
        if (
            event.event_action in {"system_boot", "system_shutdown"}
            or event.source_type in GAP_SOURCE_TYPES
            and any(marker in event.summary.lower() for marker in BOOT_MARKERS)
        ):
            boots.append(moment)
    return sorted(boots)


def check_log_gaps(
    events: Sequence[TimelineEvent], sources: Sequence[Any], host: str
) -> list[TimelineEvent]:
    """A busy log that goes silent while the host stays up deserves a look."""
    by_source: dict[str, list[float]] = defaultdict(list)
    paths: dict[str, str] = {}
    activity: list[tuple[float, str]] = []
    for event in events:
        moment = _epoch(event)
        if moment is None or event.timestamp_type != "log_time":
            continue
        activity.append((moment, event.source_type))
        if event.source_type in GAP_SOURCE_TYPES:
            by_source[event.source_type].append(moment)
            paths.setdefault(event.source_type, event.source_path)
    activity.sort()
    activity_times = [moment for moment, _ in activity]
    boots = _boot_times(events)
    findings = []
    for source_type, times in by_source.items():
        if len(times) < GAP_MIN_EVENTS:
            continue
        times.sort()
        gaps = [(later - earlier, earlier, later) for earlier, later in pairwise(times)]
        typical = median(gap for gap, _, _ in gaps)
        threshold = max(GAP_MIN_SECONDS, GAP_MEDIAN_FACTOR * typical)
        candidates = sorted((g for g in gaps if g[0] >= threshold), reverse=True)
        for length, start, end in candidates[:MAX_GAPS_PER_SOURCE]:
            low = bisect_left(boots, start - GAP_BOOT_SLACK_SECONDS)
            if low < len(boots) and boots[low] <= end + GAP_BOOT_SLACK_SECONDS:
                continue  # The host was down or restarting: the silence is explained.
            first = bisect_right(activity_times, start)
            last = bisect_left(activity_times, end)
            others = [kind for _, kind in activity[first:last] if kind != source_type]
            alive = len(others) >= GAP_ACTIVITY_MIN_EVENTS
            other_kinds = ", ".join(sorted(set(others))[:4])
            findings.append(
                _finding(
                    host=host,
                    epoch=start,
                    action="log_gap_while_host_active" if alive else "log_gap",
                    severity="medium" if alive else "low",
                    confidence="medium" if alive else "low",
                    summary=(
                        f"{source_type} has no entries for {_duration(length)} "
                        f"({_iso(start)} to {_iso(end)}); its typical spacing is "
                        f"{typical:.0f} s. "
                        + (
                            f"{len(others)} event(s) from {other_kinds} fall inside the gap, "
                            "so the host was running and no boot or shutdown explains the silence."
                            if alive
                            else "No boot or shutdown was recorded around it, and no other "
                            "source shows activity, so the host may simply have been idle."
                        )
                    ),
                    sources=[paths[source_type]],
                    mitre=("T1070",),
                    extra={
                        "gap_start": _iso(start),
                        "gap_end": _iso(end),
                        "gap_seconds": int(length),
                        "typical_spacing_seconds": round(typical, 1),
                        "other_events_in_gap": len(others),
                    },
                )
            )
    return findings


def check_journal_sequence(
    events: Sequence[TimelineEvent], sources: Sequence[Any], host: str
) -> list[TimelineEvent]:
    """Journal sequence numbers are shared by every file of one journald instance."""
    sequences: dict[str, list[tuple[int, float, str]]] = defaultdict(list)
    for event in events:
        if (
            event.source_type != "journal_binary"
            or event.event_action == "journal_partially_decoded"
        ):
            continue
        moment = _epoch(event)
        seqnum = event.extra.get("seqnum")
        seqnum_id = str(event.extra.get("seqnum_id") or "")
        if moment is not None and isinstance(seqnum, int) and seqnum_id:
            sequences[seqnum_id].append((seqnum, moment, event.source_path))
    findings = []
    for seqnum_id, entries in sequences.items():
        entries.sort()
        gaps = [
            (later[0] - earlier[0] - 1, earlier, later)
            for earlier, later in pairwise(entries)
            if later[0] - earlier[0] > 1
        ]
        if not gaps:
            continue
        missing = sum(gap for gap, _, _ in gaps)
        largest = sorted(gaps, key=lambda item: item[0], reverse=True)[:5]
        detail = "; ".join(
            f"{count} after #{earlier[0]} ({_iso(earlier[1])})"
            for count, earlier, _ in largest
        )
        findings.append(
            _finding(
                host=host,
                epoch=largest[0][1][1],
                action="journal_sequence_gap",
                severity="low",
                confidence="low",
                summary=(
                    f"{missing} journal entries are absent from the collected files in "
                    f"{len(gaps)} gap(s). Largest: {detail}. The missing entries were written "
                    "to a journal file that is not in the collection: deleted, vacuumed, "
                    "or not collected."
                ),
                sources=list(dict.fromkeys(path for _, _, path in entries))[:6],
                mitre=("T1070",),
                extra={
                    "seqnum_id": seqnum_id,
                    "missing_entries": missing,
                    "gaps": len(gaps),
                    "first_seqnum": entries[0][0],
                    "last_seqnum": entries[-1][0],
                },
            )
        )
    return findings


CHECKS = (
    check_lastlog_against_wtmp,
    check_wtmp_against_auth_log,
    check_log_gaps,
    check_journal_sequence,
)


def run_integrity_checks(
    events: Sequence[TimelineEvent], sources: Sequence[Any], host: str = ""
) -> list[TimelineEvent]:
    findings: list[TimelineEvent] = []
    for check in CHECKS:
        findings.extend(check(events, sources, host))
    return findings
