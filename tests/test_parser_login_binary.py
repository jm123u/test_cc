from __future__ import annotations

import gzip
import json
import struct
import tempfile
import unittest
from pathlib import Path

from uac_parser.loaders.uac_layout import discover_sources
from uac_parser.parsers import utmp
from uac_parser.pipeline import run_pipeline

T0 = 1_772_356_500  # 2026-03-01T09:15:00Z
TIME32 = "hxxi32s4s32s256shhiii16s20x"
TIME64 = "hxxi32s4s32s256shhqqq16s20x4x"


def record(
    record_type: int,
    seconds: int,
    *,
    user: str = "",
    line: str = "",
    host: str = "",
    address: bytes = bytes(16),
    pid: int = 0,
    usec: int = 0,
    layout: str = "<" + TIME32,
) -> bytes:
    return struct.pack(
        layout,
        record_type,
        pid,
        line.encode(),
        line[-4:].encode(),
        user.encode(),
        host.encode(),
        0,
        0,
        0,
        seconds,
        usec,
        address,
    )


def ipv4(text: str) -> bytes:
    return bytes(int(part) for part in text.split(".")) + bytes(12)


def sample(layout: str = "<" + TIME32) -> list[bytes]:
    return [
        record(
            utmp.BOOT_TIME,
            T0 - 600,
            user="reboot",
            line="~",
            host="6.8.0",
            layout=layout,
        ),
        record(
            utmp.USER_PROCESS,
            T0,
            user="alice",
            line="pts/0",
            host="203.0.113.7",
            address=ipv4("203.0.113.7"),
            pid=4242,
            usec=250000,
            layout=layout,
        ),
        record(utmp.DEAD_PROCESS, T0 + 1800, line="pts/0", pid=4242, layout=layout),
        record(
            utmp.USER_PROCESS,
            T0 + 3600,
            user="root",
            line="pts/1",
            host="2001:db8::5",
            address=bytes.fromhex("20010db8000000000000000000000005"),
            layout=layout,
        ),
    ]


def parse_bytes(data: bytes, name: str = "wtmp") -> list:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / name
        path.write_bytes(data)
        return utmp.parse(path, f"var/log/{name}", host="web01")


class LoginBinaryParserTests(unittest.TestCase):
    def test_wtmp_sessions_boot_and_addresses(self) -> None:
        boot, login, logout, root = parse_bytes(b"".join(sample()))

        self.assertEqual(boot.event_action, "system_boot")
        self.assertEqual(login.event_action, "login_session")
        self.assertEqual(login.timestamp, "2026-03-01T09:15:00.250000Z")
        self.assertEqual(login.timezone_confidence, "source_epoch")
        self.assertEqual(
            (login.user, login.src_ip, login.pid), ("alice", "203.0.113.7", "4242")
        )
        self.assertEqual(login.extra["tty"], "pts/0")
        self.assertEqual(login.extra["record_layout"], "time32-le")
        self.assertEqual(login.source_type, "login_binary")
        self.assertEqual(logout.event_action, "logout_session")
        self.assertEqual(root.src_ip, "2001:db8::5")
        self.assertEqual(root.mitre, ["T1078"])

    def test_layouts_for_other_architectures_are_detected(self) -> None:
        for name, layout, size in (
            ("time64-le", "<" + TIME64, 400),
            ("time32-be", ">" + TIME32, 384),
            ("time64-be", ">" + TIME64, 400),
        ):
            with self.subTest(layout=name):
                data = b"".join(sample(layout))
                self.assertEqual(len(data), 4 * size)
                events = parse_bytes(data)
                self.assertEqual(
                    [event.event_action for event in events],
                    ["system_boot", "login_session", "logout_session", "login_session"],
                )
                self.assertEqual(events[1].extra["record_layout"], name)
                self.assertEqual(events[1].timestamp, "2026-03-01T09:15:00.250000Z")

    def test_btmp_records_are_failed_logins(self) -> None:
        data = record(
            utmp.LOGIN_PROCESS,
            T0,
            user="admin",
            line="ssh:notty",
            host="198.51.100.8",
            address=ipv4("198.51.100.8"),
        )
        (event,) = parse_bytes(data, "btmp")

        self.assertEqual(event.event_action, "login_failed")
        self.assertEqual((event.user, event.src_ip), ("admin", "198.51.100.8"))
        self.assertEqual(event.detection_names, ["failed_login_history"])
        self.assertEqual(event.mitre, ["T1110"])

    def test_zeroed_records_are_reported_as_log_tampering(self) -> None:
        records = sample()
        records[3] = bytes(384)
        records.append(record(utmp.USER_PROCESS, T0 + 7200, user="bob", line="pts/2"))

        events = parse_bytes(b"".join(records))
        (zeroed,) = [e for e in events if e.event_action == "login_records_zeroed"]

        self.assertEqual(zeroed.severity, "high")
        self.assertEqual(zeroed.evidence_role, "inference")
        self.assertEqual(zeroed.mitre, ["T1070.002"])
        self.assertEqual(zeroed.extra["zeroed_records"], 1)
        self.assertEqual(zeroed.extra["record_offset"], 3 * 384)
        self.assertEqual(zeroed.extra["previous_record_time"], "2026-03-01T09:45:00Z")
        self.assertEqual(zeroed.extra["next_record_time"], "2026-03-01T11:15:00Z")
        self.assertNotIn("root", [event.user for event in events])

    def test_time_regression_and_truncation_are_reported(self) -> None:
        records = sample()
        records.append(record(utmp.USER_PROCESS, T0 - 86400, user="bob", line="pts/2"))

        events = parse_bytes(b"".join(records) + b"\x07\x00\x00")
        actions = [event.event_action for event in events]

        self.assertIn("login_record_time_regression", actions)
        regression = events[actions.index("login_record_time_regression")]
        self.assertEqual(regression.extra["regression_seconds"], 86400 + 3600)
        self.assertEqual(actions[-1], "login_database_truncated")
        self.assertEqual(events[-1].extra["trailing_bytes"], 3)

    def test_clock_records_do_not_raise_regressions(self) -> None:
        records = [
            record(utmp.USER_PROCESS, T0, user="alice", line="pts/0"),
            record(utmp.BOOT_TIME, T0 - 9000, user="reboot", line="~"),
            record(utmp.USER_PROCESS, T0 - 8000, user="alice", line="pts/0"),
        ]

        actions = [event.event_action for event in parse_bytes(b"".join(records))]

        self.assertNotIn("login_record_time_regression", actions)

    def test_compressed_rotation_is_read(self) -> None:
        events = parse_bytes(gzip.compress(b"".join(sample())), "wtmp.1.gz")

        self.assertEqual(len(events), 4)

    def test_lastlog_maps_uids_through_collected_passwd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "var/log").mkdir(parents=True)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_text(
                "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n"
            )
            for layout, size in (("<i32s256s", 292), ("<q32s256s", 296)):
                with self.subTest(size=size):
                    data = bytearray(size * 1001)
                    struct.pack_into(
                        layout, data, 1000 * size, T0, b"pts/0", b"203.0.113.7"
                    )
                    (root / "var/log/lastlog").write_bytes(data)

                    (event,) = utmp.parse(root / "var/log/lastlog", "var/log/lastlog")

                    self.assertEqual(event.event_action, "last_login_record")
                    self.assertEqual((event.user, event.uid), ("alice", "1000"))
                    self.assertEqual(event.src_ip, "203.0.113.7")
                    self.assertEqual(event.timestamp, "2026-03-01T09:15:00Z")
                    self.assertEqual(event.evidence_role, "state")

    def test_unrecognized_layout_is_an_error_and_empty_file_is_not(self) -> None:
        with self.assertRaises(ValueError):
            parse_bytes(b"\xff" * 384 * 3)
        self.assertEqual(parse_bytes(b""), [])

    def test_discovery_separates_native_databases_from_text_exports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "var/log").mkdir(parents=True)
            (root / "live_response").mkdir()
            for name in ("wtmp", "wtmp.1", "btmp", "lastlog"):
                (root / "var/log" / name).write_bytes(b"".join(sample()))
            (root / "live_response/wtmp.txt").write_text("alice pts/0 203.0.113.7\n")

            sources = discover_sources(root)

        native = sorted(s.relative for s in sources if s.source_type == "login_binary")
        text = [s.relative for s in sources if s.source_type == "login_history"]
        self.assertEqual(
            native,
            ["var/log/btmp", "var/log/lastlog", "var/log/wtmp", "var/log/wtmp.1"],
        )
        self.assertEqual(text, ["live_response/wtmp.txt"])

    def test_pipeline_parses_native_login_databases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "collection"
            (root / "var/log").mkdir(parents=True)
            records = sample()
            records[2] = bytes(384)
            (root / "var/log/wtmp").write_bytes(b"".join(records))
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
            if item["source_type"] == "login_binary"
        )
        self.assertEqual(result.errors, 0)
        self.assertEqual(source["parser_status"], "parsed")
        actions = [event["event_action"] for event in timeline]
        self.assertIn("login_session", actions)
        self.assertIn("login_records_zeroed", actions)


if __name__ == "__main__":
    unittest.main()
