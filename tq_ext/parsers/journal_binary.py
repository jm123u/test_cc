"""Read-only decoder for native systemd journal files (``*.journal``).

The decoder walks the object arena sequentially instead of following the entry
array index, so entries are recovered in the order journald appended them and a
damaged index or an unclean (online) file does not hide readable entries. It
supports regular and compact files, keyed-hash files, and XZ, LZ4, and
Zstandard compressed payloads. Zstandard needs Python 3.14 or the optional
``zstandard`` package; when no decoder is available, affected fields are
counted and reported instead of being dropped silently.

Reference: https://systemd.io/JOURNAL_FILE_FORMAT/
"""

from __future__ import annotations

import lzma
import mmap
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from uac_parser.parsers.journal import _classify
from uac_parser.timeline.event import TimelineEvent

SIGNATURE = b"LPKSHHRH"
HEADER_MIN_SIZE = 208
OBJECT_HEADER = struct.Struct("<BB6xQ")
ENTRY_HEADER = struct.Struct("<QQQ16sQ")
U64 = struct.Struct("<Q")

OBJECT_DATA = 1
OBJECT_ENTRY = 3
OBJECT_TYPE_MAX = 7
OBJECT_COMPRESSED_XZ = 1
OBJECT_COMPRESSED_LZ4 = 2
OBJECT_COMPRESSED_ZSTD = 4
OBJECT_COMPRESSION_MASK = 7

INCOMPATIBLE_COMPRESSED_XZ = 1
INCOMPATIBLE_COMPRESSED_LZ4 = 2
INCOMPATIBLE_KEYED_HASH = 4
INCOMPATIBLE_COMPRESSED_ZSTD = 8
INCOMPATIBLE_COMPACT = 16
INCOMPATIBLE_SUPPORTED = 31

STATE_NAMES = {0: "offline", 1: "online", 2: "archived"}

DATA_PAYLOAD_OFFSET = 64
DATA_PAYLOAD_OFFSET_COMPACT = 72
ENTRY_ITEMS_OFFSET = 64
MAX_FIELD_BYTES = 1024 * 1024
MAX_SUMMARY_CHARS = 8192
MAX_ENTRY_ITEMS = 4096
MAX_CACHED_FIELD_BYTES = 256
MAX_CACHE_ENTRIES = 250_000
MIN_REALTIME_USEC = 315532800 * 1_000_000  # 1980-01-01
MAX_REALTIME_USEC = 4102444800 * 1_000_000  # 2100-01-01

# Trusted and well-known fields preserved alongside the normalized columns.
EXTRA_FIELDS = {
    "_SYSTEMD_UNIT": "systemd_unit",
    "_SYSTEMD_USER_UNIT": "systemd_user_unit",
    "_EXE": "exe",
    "_CMDLINE": "cmdline",
    "_TRANSPORT": "transport",
    "_BOOT_ID": "boot_id",
    "_MACHINE_ID": "machine_id",
    "_AUDIT_LOGINUID": "audit_loginuid",
    "_AUDIT_SESSION": "audit_session",
    "_SOURCE_REALTIME_TIMESTAMP": "source_realtime_usec",
    "_SELINUX_CONTEXT": "selinux_context",
    "_SYSTEMD_CGROUP": "cgroup",
    "PRIORITY": "priority",
    "SYSLOG_FACILITY": "syslog_facility",
    "MESSAGE_ID": "message_id",
    "UNIT": "unit",
    "USER_UNIT": "user_unit",
    "CODE_FUNC": "code_function",
}


class JournalFormatError(ValueError):
    pass


class _FieldUnavailable(Exception):
    """A field payload could not be decoded; ``reason`` names the cause."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class JournalStats:
    state: str = ""
    compact: bool = False
    keyed_hash: bool = False
    header_entries: int = 0
    entries: int = 0
    entries_without_message: int = 0
    undecoded_fields: dict[str, int] = field(default_factory=dict)
    damaged_objects: int = 0
    truncated: bool = False


def _zstd_decoder() -> Callable[[bytes, int], bytes] | None:
    try:
        from compression import zstd as stdlib_zstd  # type: ignore[import-not-found]
    except ImportError:
        stdlib_zstd = None
    if stdlib_zstd is not None:

        def decode_stdlib(payload: bytes, limit: int) -> bytes:
            return stdlib_zstd.ZstdDecompressor().decompress(payload, max_length=limit)

        return decode_stdlib
    try:
        import zstandard  # type: ignore[import-not-found,import-untyped,unused-ignore]
    except ImportError:
        return None

    def decode_package(payload: bytes, limit: int) -> bytes:
        decompressor = zstandard.ZstdDecompressor().decompressobj()
        return bytes(decompressor.decompress(payload)[:limit])

    return decode_package


ZSTD_DECODER = _zstd_decoder()


def lz4_block_decompress(payload: bytes, expected: int) -> bytes:
    """Decode one raw LZ4 block (the journal stores the length separately)."""
    output = bytearray()
    position = 0
    end = len(payload)
    while position < end:
        token = payload[position]
        position += 1
        literal_length = token >> 4
        if literal_length == 15:
            while True:
                extra = payload[position]
                position += 1
                literal_length += extra
                if extra != 255:
                    break
        if position + literal_length > end:
            raise ValueError("LZ4 literal run exceeds the block")
        output += payload[position : position + literal_length]
        position += literal_length
        if len(output) > expected:
            raise ValueError("LZ4 block exceeds the declared size")
        if position >= end:
            break
        distance = payload[position] | (payload[position + 1] << 8)
        position += 2
        if distance == 0 or distance > len(output):
            raise ValueError("LZ4 match offset is outside the decoded data")
        match_length = token & 15
        if match_length == 15:
            while True:
                extra = payload[position]
                position += 1
                match_length += extra
                if extra != 255:
                    break
        match_length += 4
        if len(output) + match_length > expected:
            raise ValueError("LZ4 block exceeds the declared size")
        start = len(output) - distance
        if distance >= match_length:
            output += output[start : start + match_length]
        else:
            for index in range(match_length):
                output.append(output[start + index])
    return bytes(output)


def _decompress(flags: int, payload: bytes) -> bytes:
    compression = flags & OBJECT_COMPRESSION_MASK
    if compression == OBJECT_COMPRESSED_XZ:
        try:
            return lzma.LZMADecompressor(format=lzma.FORMAT_XZ).decompress(
                payload, max_length=MAX_FIELD_BYTES
            )
        except lzma.LZMAError as exc:
            raise _FieldUnavailable("corrupt_xz") from exc
    if compression == OBJECT_COMPRESSED_LZ4:
        if len(payload) < 8:
            raise _FieldUnavailable("corrupt_lz4")
        expected = U64.unpack_from(payload)[0]
        if expected > MAX_FIELD_BYTES:
            raise _FieldUnavailable("oversized_field")
        try:
            return lz4_block_decompress(payload[8:], expected)
        except (ValueError, IndexError) as exc:
            raise _FieldUnavailable("corrupt_lz4") from exc
    if compression == OBJECT_COMPRESSED_ZSTD:
        if ZSTD_DECODER is None:
            raise _FieldUnavailable("zstd_decoder_missing")
        try:
            return ZSTD_DECODER(payload, MAX_FIELD_BYTES)
        except Exception as exc:
            raise _FieldUnavailable("corrupt_zstd") from exc
    raise _FieldUnavailable("unknown_compression")


class JournalReader:
    """Sequential reader over one memory-mapped journal file."""

    def __init__(self, buffer: mmap.mmap | bytes) -> None:
        self.buffer = buffer
        self.size = len(buffer)
        if self.size < HEADER_MIN_SIZE or buffer[:8] != SIGNATURE:
            raise JournalFormatError("Not a systemd journal file.")
        incompatible = struct.unpack_from("<I", buffer, 12)[0]
        if incompatible & ~INCOMPATIBLE_SUPPORTED:
            raise JournalFormatError(
                f"Unsupported journal incompatible flags: 0x{incompatible:x}"
            )
        self.compact = bool(incompatible & INCOMPATIBLE_COMPACT)
        self.seqnum_id = bytes(buffer[72:88]).hex()
        self.header_size = U64.unpack_from(buffer, 88)[0]
        arena_size = U64.unpack_from(buffer, 96)[0]
        if self.header_size < HEADER_MIN_SIZE or self.header_size > self.size:
            raise JournalFormatError("Journal header size is out of range.")
        self.arena_end = min(self.size, self.header_size + arena_size)
        self.stats = JournalStats(
            state=STATE_NAMES.get(buffer[16], f"unknown_{buffer[16]}"),
            compact=self.compact,
            keyed_hash=bool(incompatible & INCOMPATIBLE_KEYED_HASH),
            header_entries=U64.unpack_from(buffer, 152)[0],
            truncated=self.header_size + arena_size > self.size,
        )
        self._payload_offset = (
            DATA_PAYLOAD_OFFSET_COMPACT if self.compact else DATA_PAYLOAD_OFFSET
        )
        self._item = struct.Struct("<I" if self.compact else "<Q8x")
        self._cache: dict[int, tuple[str, str]] = {}

    def entries(self) -> Iterator[tuple[int, int, int, bytes, dict[str, str]]]:
        """Yield ``(offset, seqnum, realtime_usec, boot_id, fields)`` in file order."""
        offset = self.header_size
        while offset + OBJECT_HEADER.size <= self.arena_end:
            object_type, _flags, size = OBJECT_HEADER.unpack_from(self.buffer, offset)
            if (
                size < OBJECT_HEADER.size
                or offset + size > self.arena_end
                or object_type == 0
                or object_type > OBJECT_TYPE_MAX
            ):
                # An online file can end in a partially written object, and a
                # damaged region cannot be skipped reliably without its size.
                if any(self.buffer[offset : min(offset + 64, self.arena_end)]):
                    self.stats.damaged_objects += 1
                break
            if object_type == OBJECT_ENTRY and size >= ENTRY_ITEMS_OFFSET:
                entry = self._entry(offset, size)
                if entry is not None:
                    yield entry
            offset += (size + 7) & ~7

    def _entry(
        self, offset: int, size: int
    ) -> tuple[int, int, int, bytes, dict[str, str]] | None:
        seqnum, realtime, _monotonic, boot_id, _xor_hash = ENTRY_HEADER.unpack_from(
            self.buffer, offset + OBJECT_HEADER.size
        )
        if not MIN_REALTIME_USEC <= realtime < MAX_REALTIME_USEC:
            self.stats.damaged_objects += 1
            return None
        count = min((size - ENTRY_ITEMS_OFFSET) // self._item.size, MAX_ENTRY_ITEMS)
        fields: dict[str, str] = {}
        for index in range(count):
            data_offset = self._item.unpack_from(
                self.buffer, offset + ENTRY_ITEMS_OFFSET + index * self._item.size
            )[0]
            try:
                name, value = self._data(data_offset)
            except _FieldUnavailable as exc:
                undecoded = self.stats.undecoded_fields
                undecoded[exc.reason] = undecoded.get(exc.reason, 0) + 1
                continue
            if name not in fields:
                fields[name] = value
            elif name == "MESSAGE":
                fields[name] = f"{fields[name]}\n{value}"
        self.stats.entries += 1
        return offset, seqnum, realtime, boot_id, fields

    def _data(self, offset: int) -> tuple[str, str]:
        cached = self._cache.get(offset)
        if cached is not None:
            return cached
        if (
            offset < self.header_size
            or offset & 7
            or offset + self._payload_offset > self.arena_end
        ):
            raise _FieldUnavailable("dangling_reference")
        object_type, flags, size = OBJECT_HEADER.unpack_from(self.buffer, offset)
        if (
            object_type != OBJECT_DATA
            or size < self._payload_offset
            or offset + size > self.arena_end
        ):
            raise _FieldUnavailable("dangling_reference")
        length = size - self._payload_offset
        if length > MAX_FIELD_BYTES:
            raise _FieldUnavailable("oversized_field")
        payload = bytes(self.buffer[offset + self._payload_offset : offset + size])
        if flags & OBJECT_COMPRESSION_MASK:
            payload = _decompress(flags, payload)
        name_bytes, separator, value_bytes = payload.partition(b"=")
        if not separator:
            raise _FieldUnavailable("malformed_field")
        result = (
            name_bytes.decode("ascii", "replace"),
            value_bytes.decode("utf-8", "replace"),
        )
        if length <= MAX_CACHED_FIELD_BYTES and len(self._cache) < MAX_CACHE_ENTRIES:
            self._cache[offset] = result
        return result


def _iso(realtime_usec: int) -> str:
    seconds, microseconds = divmod(realtime_usec, 1_000_000)
    moment = datetime.fromtimestamp(seconds, UTC).replace(microsecond=microseconds)
    return moment.isoformat().replace("+00:00", "Z")


def _event(
    relative: str,
    host: str,
    offset: int,
    seqnum: int,
    realtime: int,
    boot_id: bytes,
    fields: dict[str, str],
    seqnum_id: str = "",
) -> TimelineEvent:
    timestamp = _iso(realtime)
    message = fields.get("MESSAGE") or "(journal entry without MESSAGE field)"
    if len(message) > MAX_SUMMARY_CHARS:
        message = message[:MAX_SUMMARY_CHARS] + " [truncated]"
    process = (
        fields.get("SYSLOG_IDENTIFIER")
        or fields.get("_COMM")
        or fields.get("_SYSTEMD_UNIT")
        or "journal"
    )
    pid = fields.get("_PID") or fields.get("SYSLOG_PID")
    entry_host = fields.get("_HOSTNAME", "")
    extra: dict[str, object] = {
        "entry_offset": offset,
        "seqnum": seqnum,
        "entry_boot_id": boot_id.hex(),
        "seqnum_id": seqnum_id,
    }
    for name, key in EXTRA_FIELDS.items():
        value = fields.get(name)
        if value:
            extra[key] = value if len(value) <= 2048 else value[:2048] + " [truncated]"
    prefix = f"{process}[{pid}]" if pid else process
    event = TimelineEvent(
        timestamp=timestamp,
        timestamp_raw=str(realtime),
        timezone="UTC",
        timezone_confidence="source_epoch",
        timestamp_type="log_time",
        timestamp_precision="microsecond",
        timestamp_confidence="high",
        evidence_role="behavior",
        host=host or entry_host,
        source_path=relative,
        source_type="journal_binary",
        parser="journal_binary",
        event_category="system",
        event_action="journal_message",
        uid=fields.get("_UID"),
        gid=fields.get("_GID"),
        process=process,
        pid=pid,
        severity="informational",
        confidence="high",
        tags=["journal"],
        summary=message,
        raw=f"{timestamp} {entry_host or host or '-'} {prefix}: {message}",
        extra=extra,
    )
    _classify(event, message)
    return event


def _coverage_event(relative: str, host: str, stats: JournalStats) -> TimelineEvent:
    undecoded = sum(stats.undecoded_fields.values())
    reasons = ", ".join(
        f"{reason}: {count}" for reason, count in sorted(stats.undecoded_fields.items())
    )
    parts = []
    if undecoded:
        parts.append(f"{undecoded} field value(s) could not be decoded ({reasons})")
    if stats.damaged_objects:
        parts.append(
            f"{stats.damaged_objects} damaged object(s) stopped or were skipped"
        )
    if stats.truncated:
        parts.append("the file is shorter than its header declares")
    if stats.header_entries > stats.entries:
        parts.append(
            f"the header declares {stats.header_entries} entries but "
            f"{stats.entries} were recovered"
        )
    hint = (
        " Install the optional 'zstandard' package to decode Zstandard fields."
        if stats.undecoded_fields.get("zstd_decoder_missing")
        else ""
    )
    summary = f"Journal decoded with gaps: {'; '.join(parts)}.{hint}"
    return TimelineEvent(
        timestamp="",
        timezone="UTC",
        timezone_confidence="missing",
        timestamp_type="unknown",
        timestamp_precision="not_applicable",
        timestamp_confidence="not_applicable",
        evidence_role="context",
        host=host,
        source_path=relative,
        source_type="journal_binary",
        parser="journal_binary",
        event_category="collection",
        event_action="journal_partially_decoded",
        severity="low",
        confidence="high",
        tags=["journal", "parser_coverage"],
        summary=summary,
        raw=summary,
        extra={
            "journal_state": stats.state,
            "compact": stats.compact,
            "header_entries": stats.header_entries,
            "recovered_entries": stats.entries,
            "undecoded_fields": dict(stats.undecoded_fields),
            "damaged_objects": stats.damaged_objects,
            "truncated": stats.truncated,
        },
    )


def parse(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    if path.stat().st_size == 0:
        return []
    events: list[TimelineEvent] = []
    with (
        path.open("rb") as handle,
        mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as buffer,
    ):
        reader = JournalReader(buffer)
        for offset, seqnum, realtime, boot_id, fields in reader.entries():
            if "MESSAGE" not in fields:
                reader.stats.entries_without_message += 1
            events.append(
                _event(
                    relative,
                    host,
                    offset,
                    seqnum,
                    realtime,
                    boot_id,
                    fields,
                    reader.seqnum_id,
                )
            )
        stats = reader.stats
    if (
        stats.undecoded_fields
        or stats.damaged_objects
        or stats.truncated
        or stats.header_entries > stats.entries
    ):
        events.append(_coverage_event(relative, host, stats))
    return events
