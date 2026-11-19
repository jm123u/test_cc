"""Build small synthetic systemd journal files for decoder tests."""

from __future__ import annotations

import lzma
import struct

OBJECT_DATA = 1
OBJECT_ENTRY = 3
HEADER_SIZE = 272
FLAG_XZ, FLAG_LZ4, FLAG_ZSTD = 1, 2, 4


def lz4_literal_block(data: bytes) -> bytes:
    """Encode data as one literal-only LZ4 block."""
    length = len(data)
    if length < 15:
        return bytes([length << 4]) + data
    remainder = length - 15
    extension = b"\xff" * (remainder // 255) + bytes([remainder % 255])
    return b"\xf0" + extension + data


class JournalBuilder:
    def __init__(self, *, compact: bool = False, state: int = 0) -> None:
        self.compact = compact
        self.state = state
        self.arena = bytearray()
        self.entries = 0
        self.incompatible = 4 | (16 if compact else 0)
        self._data: dict[tuple[bytes, str], int] = {}

    def _append(self, object_type: int, flags: int, body: bytes) -> int:
        offset = HEADER_SIZE + len(self.arena)
        size = 16 + len(body)
        self.arena += struct.pack("<BB6xQ", object_type, flags, size) + body
        self.arena += bytes(-size % 8)
        return offset

    def data(self, field: str, value: str | bytes, compression: str = "") -> int:
        raw = value.encode() if isinstance(value, str) else value
        payload = field.encode() + b"=" + raw
        key = (payload, compression)
        if key in self._data:
            return self._data[key]
        flags = 0
        if compression == "xz":
            flags, payload = FLAG_XZ, lzma.compress(payload, format=lzma.FORMAT_XZ)
            self.incompatible |= 1
        elif compression == "lz4":
            block = lz4_literal_block(payload)
            flags, payload = FLAG_LZ4, struct.pack("<Q", len(payload)) + block
            self.incompatible |= 2
        elif compression == "zstd":
            import zstandard

            flags, payload = FLAG_ZSTD, zstandard.ZstdCompressor().compress(payload)
            self.incompatible |= 8
        elif compression == "zstd-opaque":
            flags, payload = FLAG_ZSTD, b"\x28\xb5\x2f\xfd" + payload
            self.incompatible |= 8
        prefix = bytes(48) + (bytes(8) if self.compact else b"")
        offset = self._append(OBJECT_DATA, flags, prefix + payload)
        self._data[key] = offset
        return offset

    def entry(self, realtime_usec: int, fields: list[int]) -> int:
        self.entries += 1
        body = struct.pack(
            "<QQQ16sQ",
            self.entries,
            realtime_usec,
            self.entries * 1000,
            b"\xab" * 16,
            0,
        )
        for offset in fields:
            body += (
                struct.pack("<I", offset)
                if self.compact
                else struct.pack("<QQ", offset, 0)
            )
        return self._append(OBJECT_ENTRY, 0, body)

    def message(
        self, realtime_usec: int, message: str, compression: str = "", **fields: str
    ) -> int:
        items = [self.data("MESSAGE", message, compression)]
        items += [self.data(name, value) for name, value in fields.items()]
        return self.entry(realtime_usec, items)

    def build(self, *, declared_entries: int | None = None) -> bytes:
        header = bytearray(HEADER_SIZE)
        header[0:8] = b"LPKSHHRH"
        struct.pack_into("<II", header, 8, 0, self.incompatible)
        header[16] = self.state
        struct.pack_into("<QQ", header, 88, HEADER_SIZE, len(self.arena))
        entries = self.entries if declared_entries is None else declared_entries
        struct.pack_into("<Q", header, 152, entries)
        return bytes(header) + bytes(self.arena)
