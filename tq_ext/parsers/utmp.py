"""Native decoders for Linux wtmp, btmp, utmp, and lastlog databases.

The record layout depends on the collecting platform rather than on the analyst
workstation, so the decoder never uses the local C library. It recognizes the
two glibc utmp layouts (384-byte records with 32-bit time fields on x86-64 and
other compatibility ABIs, 400-byte records with 64-bit time fields on AArch64
and RISC-V), both byte orders, and the matching lastlog layouts.

Besides sessions, the decoder reports the artifacts left behind by common log
cleaners: records overwritten with zero bytes, timestamps that run backwards in
an append-only file, and truncated trailing records.
"""

from __future__ import annotations

import bz2
import gzip
import ipaddress
import lzma
import struct
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from uac_parser.parsers.common import (
    BZ2_MAGIC,
    GZIP_MAGIC,
    LZ4_MAGIC,
    XZ_MAGIC,
    ZSTD_MAGIC,
    UnsupportedCompressionError,
)
from uac_parser.timeline.event import TimelineEvent

EMPTY, RUN_LVL, BOOT_TIME, NEW_TIME, OLD_TIME = 0, 1, 2, 3, 4
INIT_PROCESS, LOGIN_PROCESS, USER_PROCESS, DEAD_PROCESS, ACCOUNTING = 5, 6, 7, 8, 9
RECORD_TYPE_NAMES = {
    EMPTY: "EMPTY",
    RUN_LVL: "RUN_LVL",
    BOOT_TIME: "BOOT_TIME",
    NEW_TIME: "NEW_TIME",
    OLD_TIME: "OLD_TIME",
    INIT_PROCESS: "INIT_PROCESS",
    LOGIN_PROCESS: "LOGIN_PROCESS",
    USER_PROCESS: "USER_PROCESS",
    DEAD_PROCESS: "DEAD_PROCESS",
    ACCOUNTING: "ACCOUNTING",
}
CLOCK_RECORD_TYPES = {RUN_LVL, BOOT_TIME, NEW_TIME, OLD_TIME}

MIN_PLAUSIBLE_EPOCH = 315532800  # 1980-01-01
MAX_PLAUSIBLE_EPOCH = 4102444800  # 2100-01-01
TIME_REGRESSION_TOLERANCE_SECONDS = 300
LAYOUT_SAMPLE_RECORDS = 512
READ_RECORDS = 1024
MAX_TAMPER_EVENTS = 200
MIN_LAYOUT_SCORE = 0.5
MAX_LASTLOG_BYTES = 2 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class UtmpLayout:
    name: str
    record: struct.Struct

    @property
    def size(self) -> int:
        return self.record.size


@dataclass(frozen=True)
class LastlogLayout:
    name: str
    record: struct.Struct

    @property
    def size(self) -> int:
        return self.record.size


# type, pid, line, id, user, host, e_termination, e_exit, session, sec, usec, addr
_UTMP_TIME32 = "hxxi32s4s32s256shhiii16s20x"
_UTMP_TIME64 = "hxxi32s4s32s256shhqqq16s20x4x"
UTMP_LAYOUTS = (
    UtmpLayout("time32-le", struct.Struct("<" + _UTMP_TIME32)),
    UtmpLayout("time64-le", struct.Struct("<" + _UTMP_TIME64)),
    UtmpLayout("time32-be", struct.Struct(">" + _UTMP_TIME32)),
    UtmpLayout("time64-be", struct.Struct(">" + _UTMP_TIME64)),
)
LASTLOG_LAYOUTS = (
    LastlogLayout("time32-le", struct.Struct("<i32s256s")),
    LastlogLayout("time64-le", struct.Struct("<q32s256s")),
    LastlogLayout("time32-be", struct.Struct(">i32s256s")),
    LastlogLayout("time64-be", struct.Struct(">q32s256s")),
)


@dataclass(frozen=True)
class UtmpRecord:
    offset: int
    type: int
    pid: int
    line: str
    id: str
    user: str
    host: str
    exit_termination: int
    exit_status: int
    session: int
    seconds: int
    microseconds: int
    address: str

    @property
    def type_name(self) -> str:
        return RECORD_TYPE_NAMES.get(self.type, f"UNKNOWN_{self.type}")


def open_binary(path: Path) -> BinaryIO:
    """Open a binary database, transparently reading compressed rotations."""
    with path.open("rb") as probe:
        magic = probe.read(6)
    if magic.startswith(GZIP_MAGIC):
        return gzip.open(path, "rb")  # type: ignore[return-value]
    if magic.startswith(BZ2_MAGIC):
        return bz2.open(path, "rb")  # type: ignore[return-value]
    if magic.startswith(XZ_MAGIC):
        return lzma.open(path, "rb")  # type: ignore[return-value]
    if magic.startswith(ZSTD_MAGIC):
        raise UnsupportedCompressionError(
            "Zstandard-compressed evidence requires an optional zstd decoder."
        )
    if magic.startswith(LZ4_MAGIC):
        raise UnsupportedCompressionError(
            "LZ4-compressed evidence requires an optional lz4 decoder."
        )
    return path.open("rb")


def parse(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    """Dispatch a native login database to the matching decoder."""
    name = Path(relative).name.lower()
    if name.startswith("lastlog"):
        return parse_lastlog(path, relative, host=host)
    return parse_utmp(path, relative, host=host)


def parse_utmp(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    name = Path(relative).name.lower()
    failed = name.startswith("btmp")
    database = "btmp" if failed else "utmp" if name.startswith("utmp") else "wtmp"
    with open_binary(path) as handle:
        sample = handle.read(LAYOUT_SAMPLE_RECORDS * 400)
        if not sample:
            return []
        layout = detect_utmp_layout(sample)
        handle.seek(0)
        events: list[TimelineEvent] = []
        tamper_events = 0
        suppressed_tamper = 0
        zero_run_start: int | None = None
        zero_run_records = 0
        previous: UtmpRecord | None = None
        records = 0
        trailing = 0

        def flush_zero_run(next_record: UtmpRecord | None) -> None:
            nonlocal zero_run_start, zero_run_records, tamper_events, suppressed_tamper
            if zero_run_start is None:
                return
            # These databases are append-only and never preallocated, so a
            # zero-filled region is reported wherever it appears.
            if tamper_events < MAX_TAMPER_EVENTS:
                events.append(
                    _zeroed_event(
                        relative,
                        host,
                        database,
                        layout,
                        zero_run_start,
                        zero_run_records,
                        previous,
                        next_record,
                    )
                )
                tamper_events += 1
            else:
                suppressed_tamper += 1
            zero_run_start = None
            zero_run_records = 0

        for offset, chunk in _iter_records(handle, layout.size):
            if len(chunk) < layout.size:
                trailing = len(chunk)
                break
            records += 1
            if not any(chunk):
                if zero_run_start is None:
                    zero_run_start = offset
                zero_run_records += 1
                continue
            record = _decode_utmp(layout, chunk, offset)
            flush_zero_run(record)
            if (
                previous is not None
                and _plausible(record.seconds)
                and _plausible(previous.seconds)
                and previous.seconds - record.seconds
                > TIME_REGRESSION_TOLERANCE_SECONDS
                and record.type not in CLOCK_RECORD_TYPES
                and previous.type not in CLOCK_RECORD_TYPES
                and database != "utmp"
            ):
                if tamper_events < MAX_TAMPER_EVENTS:
                    events.append(
                        _regression_event(
                            relative, host, database, layout, previous, record
                        )
                    )
                    tamper_events += 1
                else:
                    suppressed_tamper += 1
            event = _record_event(relative, host, database, layout, record, failed)
            if event is not None:
                events.append(event)
            if _plausible(record.seconds):
                previous = record
        flush_zero_run(None)
        if trailing:
            events.append(
                _artifact_event(
                    relative,
                    host,
                    database,
                    layout,
                    action="login_database_truncated",
                    detection="login_database_truncated",
                    severity="medium",
                    confidence="medium",
                    summary=(
                        f"{database} ends with a partial {trailing}-byte record after "
                        f"{records} complete records; the file was truncated or the "
                        "record layout was not recognized"
                    ),
                    anchor=previous,
                    extra={"trailing_bytes": trailing, "complete_records": records},
                )
            )
        if suppressed_tamper:
            events.append(
                _artifact_event(
                    relative,
                    host,
                    database,
                    layout,
                    action="login_database_anomalies_suppressed",
                    detection="login_database_anomalies_suppressed",
                    severity="medium",
                    confidence="medium",
                    summary=(
                        f"{suppressed_tamper} additional {database} integrity anomalies "
                        f"were not expanded after the first {MAX_TAMPER_EVENTS}"
                    ),
                    anchor=previous,
                    extra={"suppressed_anomalies": suppressed_tamper},
                )
            )
    return events


def detect_utmp_layout(sample: bytes) -> UtmpLayout:
    """Choose the record layout whose decoded fields are the most plausible."""
    best: tuple[float, UtmpLayout] | None = None
    for layout in UTMP_LAYOUTS:
        score = _score_utmp_layout(layout, sample)
        if best is None or score > best[0]:
            best = (score, layout)
    if best is None or best[0] < MIN_LAYOUT_SCORE:
        raise ValueError("Unrecognized utmp record layout.")
    return best[1]


def _score_utmp_layout(layout: UtmpLayout, sample: bytes) -> float:
    total = 0
    valid = 0
    for offset in range(0, len(sample) - layout.size + 1, layout.size):
        chunk = sample[offset : offset + layout.size]
        if not any(chunk):
            continue
        total += 1
        fields = layout.record.unpack(chunk)
        record_type, seconds, microseconds = fields[0], fields[9], fields[10]
        if (
            EMPTY < record_type <= ACCOUNTING
            and _plausible(seconds)
            and 0 <= microseconds < 1_000_000
            and _clean_text(fields[2])
            and _clean_text(fields[4])
            and _clean_text(fields[5])
        ):
            valid += 1
    if total == 0:
        # Entirely zero-filled sample: fall back to the most common layout.
        return 1.0 if layout.name == "time32-le" else 0.0
    score = valid / total
    if len(sample) < LAYOUT_SAMPLE_RECORDS * 400 and len(sample) % layout.size == 0:
        # The sample is the whole file and divides evenly into records.
        score += 0.01
    return score


def _clean_text(value: bytes) -> bool:
    """Fixed-width text fields hold printable text followed only by NUL padding."""
    text, _, padding = value.partition(b"\0")
    return not any(padding) and all(byte >= 0x20 and byte != 0x7F for byte in text)


def _plausible(seconds: int) -> bool:
    return MIN_PLAUSIBLE_EPOCH <= seconds < MAX_PLAUSIBLE_EPOCH


def _iter_records(handle: BinaryIO, size: int) -> Iterator[tuple[int, bytes]]:
    offset = 0
    pending = b""
    while True:
        block = handle.read(size * READ_RECORDS)
        if not block:
            break
        data = pending + block
        usable = len(data) - len(data) % size
        for start in range(0, usable, size):
            yield offset + start, data[start : start + size]
        offset += usable
        pending = data[usable:]
    if pending:
        yield offset, pending


def _text(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("utf-8", "replace").strip()


def _address(raw: bytes) -> str:
    if not any(raw):
        return ""
    if not any(raw[4:]):
        return str(ipaddress.IPv4Address(raw[:4]))
    address = ipaddress.IPv6Address(raw)
    return str(address.ipv4_mapped or address)


def _decode_utmp(layout: UtmpLayout, chunk: bytes, offset: int) -> UtmpRecord:
    (
        record_type,
        pid,
        line,
        ident,
        user,
        remote_host,
        termination,
        exit_status,
        session,
        seconds,
        microseconds,
        address,
    ) = layout.record.unpack(chunk)
    return UtmpRecord(
        offset=offset,
        type=record_type,
        pid=pid,
        line=_text(line),
        id=_text(ident),
        user=_text(user),
        host=_text(remote_host),
        exit_termination=termination,
        exit_status=exit_status,
        session=session,
        seconds=seconds,
        microseconds=microseconds if 0 <= microseconds < 1_000_000 else 0,
        address=_address(address),
    )


def _iso(seconds: int, microseconds: int = 0) -> str:
    if not _plausible(seconds):
        return ""
    moment = datetime.fromtimestamp(seconds, UTC).replace(microsecond=microseconds)
    return moment.isoformat().replace("+00:00", "Z")


def _source_address(record: UtmpRecord) -> str | None:
    if record.address:
        return record.address
    candidate = record.host.split("%", 1)[0]
    with suppress(ValueError):
        return str(ipaddress.ip_address(candidate))
    return None


def _raw(database: str, record: UtmpRecord) -> str:
    return (
        f"[{record.type}] [{record.pid:05d}] [{record.id:<4}] [{record.user:<8}] "
        f"[{record.line:<12}] [{record.host:<20}] [{record.address or '0.0.0.0':<15}] "
        f"[{_iso(record.seconds, record.microseconds) or record.seconds}]"
    )


def _base_extra(layout: UtmpLayout, record: UtmpRecord) -> dict[str, object]:
    extra: dict[str, object] = {
        "record_offset": record.offset,
        "record_type": record.type_name,
        "record_layout": layout.name,
        "tty": record.line,
    }
    if record.id:
        extra["inittab_id"] = record.id
    if record.host:
        extra["remote_host"] = record.host
    if record.session:
        extra["session_id"] = record.session
    return extra


def _record_event(
    relative: str,
    host: str,
    database: str,
    layout: UtmpLayout,
    record: UtmpRecord,
    failed: bool,
) -> TimelineEvent | None:
    timestamp = _iso(record.seconds, record.microseconds)
    extra = _base_extra(layout, record)
    category = "authentication"
    severity = "low"
    tags = ["login_history", database]
    detections: list[str] = []
    mitre: list[str] = []
    user: str | None = record.user or None
    src_ip = _source_address(record)
    origin = record.host or record.address or "local"
    if failed:
        if record.type not in {LOGIN_PROCESS, USER_PROCESS}:
            return None
        action = "login_failed"
        severity = "medium"
        detections = ["failed_login_history"]
        mitre = ["T1110"]
        summary = f"Failed login for {record.user or '(unknown)'} from {origin}"
    elif record.type == USER_PROCESS:
        action = "login_session"
        mitre = ["T1078"]
        summary = f"Login session for {record.user} from {origin} on {record.line}"
    elif record.type == DEAD_PROCESS:
        action = "logout_session"
        severity = "informational"
        user = None
        extra["exit_termination"] = record.exit_termination
        extra["exit_status"] = record.exit_status
        summary = f"Session ended on {record.line or record.id or 'unknown terminal'}"
    elif record.type == BOOT_TIME:
        category, action, user, src_ip = "system", "system_boot", None, None
        severity = "informational"
        tags.append("boot")
        extra["kernel"] = record.host
        summary = (
            f"System boot recorded ({record.host})"
            if record.host
            else "System boot recorded"
        )
    elif record.type == RUN_LVL:
        category, user, src_ip = "system", None, None
        severity = "informational"
        if record.user == "shutdown":
            action = "system_shutdown"
            tags.append("shutdown")
            summary = "System shutdown recorded"
        else:
            action = "runlevel_change"
            summary = f"Runlevel change recorded ({record.user or 'runlevel'})"
    elif record.type in {NEW_TIME, OLD_TIME}:
        category, action, user, src_ip = "system", "system_time_change", None, None
        severity = "medium"
        tags.append("time_change")
        detections = ["system_time_change"]
        mitre = ["T1070.006"]
        which = "new" if record.type == NEW_TIME else "old"
        summary = f"System clock change recorded ({which} time marker)"
    else:
        # EMPTY, INIT_PROCESS, LOGIN_PROCESS (getty), and ACCOUNTING records do
        # not describe user activity in wtmp.
        return None
    return TimelineEvent(
        timestamp=timestamp,
        timestamp_raw=str(record.seconds),
        timezone="UTC",
        timezone_confidence="source_epoch" if timestamp else "missing",
        timestamp_type="log_time" if timestamp else "unknown",
        timestamp_precision="microsecond" if timestamp else "not_applicable",
        timestamp_confidence="high" if timestamp else "not_applicable",
        host=host,
        source_path=relative,
        source_type="login_binary",
        parser="utmp",
        event_category=category,
        event_action=action,
        user=user,
        src_ip=src_ip,
        pid=str(record.pid) if record.pid else None,
        severity=severity,
        confidence="high",
        tags=tags,
        detection_names=list(detections),
        ttp_flags=list(detections),
        mitre=mitre,
        summary=summary,
        raw=_raw(database, record),
        extra=extra,
    )


def _artifact_event(
    relative: str,
    host: str,
    database: str,
    layout: UtmpLayout | LastlogLayout,
    *,
    action: str,
    detection: str,
    severity: str,
    confidence: str,
    summary: str,
    anchor: UtmpRecord | None,
    extra: dict[str, object],
) -> TimelineEvent:
    timestamp = _iso(anchor.seconds, anchor.microseconds) if anchor else ""
    return TimelineEvent(
        timestamp=timestamp,
        timestamp_raw=str(anchor.seconds) if anchor else "",
        timezone="UTC",
        timezone_confidence="source_epoch" if timestamp else "missing",
        timestamp_type="inferred_from_adjacent_record" if timestamp else "unknown",
        timestamp_precision="second" if timestamp else "not_applicable",
        timestamp_confidence="low" if timestamp else "not_applicable",
        evidence_role="inference",
        host=host,
        source_path=relative,
        source_type="login_binary",
        parser="utmp",
        event_category="defense_evasion",
        event_action=action,
        severity=severity,
        confidence=confidence,
        tags=["login_history", database, "log_integrity"],
        detection_names=[detection],
        ttp_flags=[detection],
        mitre=["T1070.002"],
        summary=summary,
        raw=summary,
        extra={"record_layout": layout.name, **extra},
    )


def _zeroed_event(
    relative: str,
    host: str,
    database: str,
    layout: UtmpLayout,
    start: int,
    count: int,
    previous: UtmpRecord | None,
    following: UtmpRecord | None,
) -> TimelineEvent:
    before = _iso(previous.seconds, previous.microseconds) if previous else ""
    after = _iso(following.seconds, following.microseconds) if following else ""
    window = (
        f"between {before} and {after}"
        if before and after
        else f"after {before}"
        if before
        else f"before {after}"
        if after
        else "at an unknown time"
    )
    return _artifact_event(
        relative,
        host,
        database,
        layout,
        action="login_records_zeroed",
        detection="login_records_zeroed",
        severity="high",
        confidence="medium",
        summary=(
            f"{count} zero-filled {database} record(s) at offset {start}, {window}; "
            "login records overwritten with zero bytes are consistent with a log cleaner"
        ),
        anchor=previous or following,
        extra={
            "record_offset": start,
            "zeroed_records": count,
            "previous_record_time": before,
            "next_record_time": after,
        },
    )


def _regression_event(
    relative: str,
    host: str,
    database: str,
    layout: UtmpLayout,
    previous: UtmpRecord,
    record: UtmpRecord,
) -> TimelineEvent:
    before = _iso(previous.seconds, previous.microseconds)
    current = _iso(record.seconds, record.microseconds)
    return _artifact_event(
        relative,
        host,
        database,
        layout,
        action="login_record_time_regression",
        detection="login_record_time_regression",
        severity="medium",
        confidence="low",
        summary=(
            f"{database} record at offset {record.offset} is dated {current}, "
            f"{previous.seconds - record.seconds} seconds before the preceding record "
            f"({before}); append-only login databases normally move forward in time"
        ),
        anchor=record,
        extra={
            "record_offset": record.offset,
            "previous_record_offset": previous.offset,
            "previous_record_time": before,
            "regression_seconds": previous.seconds - record.seconds,
        },
    )


def parse_lastlog(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    """Decode the per-UID last-login database."""
    with open_binary(path) as handle:
        sample = handle.read(296 * 4096)
        if not sample:
            return []
        layout = detect_lastlog_layout(sample)
        handle.seek(0)
        users = _passwd_users(path)
        events: list[TimelineEvent] = []
        for offset, chunk in _iter_records(handle, layout.size):
            if offset >= MAX_LASTLOG_BYTES:
                events.append(
                    _artifact_event(
                        relative,
                        host,
                        "lastlog",
                        layout,
                        action="login_database_partially_read",
                        detection="login_database_partially_read",
                        severity="low",
                        confidence="high",
                        summary=(
                            "lastlog decoding stopped at the configured "
                            f"{MAX_LASTLOG_BYTES} byte limit; higher UIDs were not read"
                        ),
                        anchor=None,
                        extra={"read_limit_bytes": MAX_LASTLOG_BYTES},
                    )
                )
                break
            if len(chunk) < layout.size or not any(chunk):
                continue
            seconds, line, remote_host = layout.record.unpack(chunk)
            if not _plausible(seconds):
                continue
            uid = offset // layout.size
            tty = _text(line)
            origin = _text(remote_host)
            user = users.get(uid)
            timestamp = _iso(seconds)
            src_ip: str | None = None
            with suppress(ValueError):
                src_ip = str(ipaddress.ip_address(origin.split("%", 1)[0]))
            label = f"{user} (uid {uid})" if user else f"uid {uid}"
            events.append(
                TimelineEvent(
                    timestamp=timestamp,
                    timestamp_raw=str(seconds),
                    timezone="UTC",
                    timezone_confidence="source_epoch",
                    timestamp_type="last_login_time",
                    timestamp_precision="second",
                    timestamp_confidence="high",
                    evidence_role="state",
                    host=host,
                    source_path=relative,
                    source_type="login_binary",
                    parser="utmp",
                    event_category="authentication",
                    event_action="last_login_record",
                    user=user,
                    uid=str(uid),
                    src_ip=src_ip,
                    severity="low",
                    confidence="high",
                    tags=["login_history", "lastlog"],
                    mitre=["T1078"],
                    summary=f"Most recent login for {label} from {origin or 'local'} on {tty}",
                    raw=f"[uid {uid}] [{tty}] [{origin}] [{timestamp}]",
                    extra={
                        "record_offset": offset,
                        "record_layout": layout.name,
                        "tty": tty,
                        "remote_host": origin,
                    },
                )
            )
    return events


def detect_lastlog_layout(sample: bytes) -> LastlogLayout:
    best: tuple[float, LastlogLayout] | None = None
    for layout in LASTLOG_LAYOUTS:
        total = 0
        valid = 0
        for offset in range(0, len(sample) - layout.size + 1, layout.size):
            chunk = sample[offset : offset + layout.size]
            if not any(chunk):
                continue
            total += 1
            seconds, line, remote_host = layout.record.unpack(chunk)
            if _plausible(seconds) and _clean_text(line) and _clean_text(remote_host):
                valid += 1
        score = valid / total if total else (1.0 if layout.name == "time32-le" else 0.0)
        if best is None or score > best[0]:
            best = (score, layout)
    if best is None or best[0] < MIN_LAYOUT_SCORE:
        raise ValueError("Unrecognized lastlog record layout.")
    return best[1]


def _passwd_users(lastlog_path: Path) -> dict[int, str]:
    """Map UIDs to names using the passwd file from the same collection root."""
    users: dict[int, str] = {}
    parents = lastlog_path.resolve().parents
    if len(parents) < 3:
        return users
    passwd = parents[2] / "etc" / "passwd"
    if parents[1].name != "var" or not passwd.is_file() or passwd.is_symlink():
        return users
    with suppress(OSError), passwd.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parts = line.rstrip("\n").split(":")
            if len(parts) >= 3 and parts[2].isdigit():
                users.setdefault(int(parts[2]), parts[0])
    return users
