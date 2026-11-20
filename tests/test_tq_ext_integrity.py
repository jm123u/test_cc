from __future__ import annotations

import json
import struct
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from tests.journal_fixture import JournalBuilder
from tests.test_parser_login_binary import ipv4, record
from tq_ext import integrity
from tq_ext.artifact_view import artifact_view_for_timeline
from tq_ext.parsers import utmp
from uac_parser.pipeline import run_pipeline
from uac_parser.timeline.event import TimelineEvent

T0 = 1_772_356_500  # 2026-03-01T09:15:00Z


@dataclass
class Source:
    relative: str
    source_type: str = "login_binary"
    size: int = 0
    event_count: int = 0


def iso(epoch: int) -> str:
    return integrity._iso(epoch)


def wtmp_login(
    epoch: int, user: str, tty: str = "pts/0", src: str = "203.0.113.7"
) -> TimelineEvent:
    return TimelineEvent(
        timestamp=iso(epoch),
        source_type="login_binary",
        source_path="var/log/wtmp",
        event_action="login_session",
        user=user,
        src_ip=src,
        tags=["login_history", "wtmp"],
        extra={"tty": tty},
    )


def lastlog(epoch: int, user: str | None, tty: str = "pts/0") -> TimelineEvent:
    return TimelineEvent(
        timestamp=iso(epoch),
        source_type="login_binary",
        source_path="var/log/lastlog",
        event_action="last_login_record",
        user=user,
        uid="0",
        src_ip="203.0.113.7",
        tags=["login_history", "lastlog"],
        extra={"tty": tty},
    )


def log_event(
    epoch: int, source_type: str = "syslog", **fields: object
) -> TimelineEvent:
    return TimelineEvent(
        timestamp=iso(epoch),
        timestamp_type="log_time",
        source_type=source_type,
        source_path=f"var/log/{source_type}",
        **fields,  # type: ignore[arg-type]
    )


class LastlogAgainstWtmpTests(unittest.TestCase):
    def test_missing_wtmp_record_is_reported(self) -> None:
        events = [
            wtmp_login(T0 - 3600, "alice"),
            lastlog(T0 - 3590, "alice"),
            lastlog(T0, "root"),
        ]

        (finding,) = integrity.check_lastlog_against_wtmp(events, [], "web01")

        self.assertEqual(finding.event_action, "lastlog_login_missing_from_wtmp")
        self.assertEqual((finding.severity, finding.user), ("high", "root"))
        self.assertEqual(finding.timestamp, iso(T0))
        self.assertEqual(finding.source_path, "var/log/lastlog vs var/log/wtmp")
        self.assertEqual(finding.evidence_role, "inference")
        self.assertIn("log_integrity", finding.tags)

    def test_records_older_than_wtmp_history_are_not_judged(self) -> None:
        events = [wtmp_login(T0, "alice"), lastlog(T0 - 86400, "root")]

        self.assertEqual(integrity.check_lastlog_against_wtmp(events, [], ""), [])

    def test_unknown_account_names_fall_back_to_the_terminal(self) -> None:
        matched = [
            wtmp_login(T0, "alice", tty="pts/3"),
            lastlog(T0 + 5, None, tty="pts/3"),
        ]
        unmatched = [
            wtmp_login(T0, "alice", tty="pts/3"),
            lastlog(T0 + 5, None, tty="pts/9"),
        ]

        self.assertEqual(integrity.check_lastlog_against_wtmp(matched, [], ""), [])
        self.assertEqual(
            len(integrity.check_lastlog_against_wtmp(unmatched, [], "")), 1
        )

    def test_empty_wtmp_is_reported_only_when_the_file_was_collected(self) -> None:
        events = [lastlog(T0, "root")]

        self.assertEqual(integrity.check_lastlog_against_wtmp(events, [], ""), [])
        (finding,) = integrity.check_lastlog_against_wtmp(
            events, [Source("var/log/wtmp")], ""
        )
        self.assertEqual(finding.event_action, "wtmp_empty_with_lastlog_records")
        self.assertEqual(finding.severity, "medium")


class WtmpAgainstAuthLogTests(unittest.TestCase):
    def test_login_without_auth_entries_is_reported(self) -> None:
        events = [
            log_event(T0 + offset, "auth_log") for offset in (-7200, -3600, 0, 7200)
        ]
        events += [wtmp_login(T0 + 10, "alice"), wtmp_login(T0 + 1800, "root", "pts/1")]

        (finding,) = integrity.check_wtmp_against_auth_log(events, [], "web01")

        self.assertEqual(finding.event_action, "wtmp_login_missing_from_auth_log")
        self.assertEqual((finding.user, finding.severity), ("root", "high"))

    def test_logins_outside_auth_coverage_are_not_judged(self) -> None:
        events = [log_event(T0, "auth_log"), log_event(T0 + 60, "auth_log")]
        events.append(wtmp_login(T0 + 86400, "root"))

        self.assertEqual(integrity.check_wtmp_against_auth_log(events, [], ""), [])

    def test_broad_mismatch_points_at_the_timezone_instead(self) -> None:
        events = [log_event(T0, "auth_log"), log_event(T0 + 40000, "auth_log")]
        events += [wtmp_login(T0 + 3600 * hour, f"user{hour}") for hour in range(1, 6)]

        (finding,) = integrity.check_wtmp_against_auth_log(events, [], "")

        self.assertEqual(
            finding.event_action, "wtmp_and_auth_log_disagree_systematically"
        )
        self.assertEqual(finding.severity, "low")
        self.assertIn("timezone", finding.summary)

    def test_journal_auth_processes_count_as_auth_records(self) -> None:
        events = [
            log_event(T0 - 100, "journal_binary", process="sshd"),
            log_event(T0 + 5, "journal_binary", process="sshd"),
            log_event(T0 + 900, "journal_binary", process="cron"),
            log_event(T0 + 4000, "journal_binary", process="sshd"),
            wtmp_login(T0, "alice"),
        ]

        self.assertEqual(integrity.check_wtmp_against_auth_log(events, [], ""), [])


class LogGapTests(unittest.TestCase):
    def busy_log(self, gap_start: int, gap_seconds: int) -> list[TimelineEvent]:
        before = [log_event(T0 + index * 30) for index in range(200)]
        after = [
            log_event(gap_start + gap_seconds + index * 30) for index in range(200)
        ]
        return before + after

    def test_gap_with_other_activity_is_flagged(self) -> None:
        gap_start = T0 + 199 * 30
        events = self.busy_log(gap_start, 4 * 3600)
        events += [log_event(gap_start + 600 * n, "auth_log") for n in range(1, 5)]

        (finding,) = integrity.check_log_gaps(events, [], "web01")

        self.assertEqual(finding.event_action, "log_gap_while_host_active")
        self.assertEqual((finding.severity, finding.confidence), ("medium", "medium"))
        self.assertEqual(finding.extra["gap_seconds"], 4 * 3600)
        self.assertEqual(finding.extra["other_events_in_gap"], 4)
        self.assertEqual(finding.timestamp, iso(gap_start))

    def test_quiet_gap_is_low_and_boot_explains_a_gap(self) -> None:
        gap_start = T0 + 199 * 30
        quiet = self.busy_log(gap_start, 4 * 3600)

        (finding,) = integrity.check_log_gaps(quiet, [], "")
        self.assertEqual((finding.event_action, finding.severity), ("log_gap", "low"))

        boot = TimelineEvent(
            timestamp=iso(gap_start + 4 * 3600 - 60), event_action="system_boot"
        )
        self.assertEqual(integrity.check_log_gaps([*quiet, boot], [], ""), [])

    def test_sparse_and_steady_logs_are_ignored(self) -> None:
        sparse = [log_event(T0 + index * 86400) for index in range(20)]
        steady = [log_event(T0 + index * 60) for index in range(500)]

        self.assertEqual(integrity.check_log_gaps(sparse, [], ""), [])
        self.assertEqual(integrity.check_log_gaps(steady, [], ""), [])


class JournalSequenceTests(unittest.TestCase):
    def test_gaps_are_summarized_per_journald_instance(self) -> None:
        events = [
            TimelineEvent(
                timestamp=iso(T0 + seqnum),
                source_type="journal_binary",
                source_path="var/log/journal/id/system.journal",
                extra={"seqnum": seqnum, "seqnum_id": "aa"},
            )
            for seqnum in (1, 2, 3, 10, 11, 14)
        ]

        (finding,) = integrity.check_journal_sequence(events, [], "web01")

        self.assertEqual(finding.event_action, "journal_sequence_gap")
        self.assertEqual(finding.severity, "low")
        self.assertEqual(
            (finding.extra["missing_entries"], finding.extra["gaps"]), (8, 2)
        )
        self.assertEqual(finding.timestamp, iso(T0 + 3))
        self.assertEqual(integrity.check_journal_sequence(events[:3], [], ""), [])


class PipelineIntegrationTests(unittest.TestCase):
    def test_removed_wtmp_record_surfaces_in_timeline_and_artifact_view(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "collection"
            (root / "var/log/journal/id").mkdir(parents=True)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_text(
                "root:x:0:0::/root:/bin/sh\n", encoding="utf-8"
            )
            (root / "var/log/wtmp").write_bytes(
                record(utmp.BOOT_TIME, T0 - 9000, user="reboot", line="~")
                + record(
                    utmp.USER_PROCESS,
                    T0 - 3600,
                    user="alice",
                    line="pts/0",
                    host="203.0.113.7",
                    address=ipv4("203.0.113.7"),
                )
            )
            (root / "var/log/lastlog").write_bytes(
                struct.pack("<i32s256s", T0, b"pts/1", b"203.0.113.7")
            )
            (root / "var/log/journal/id/system.journal").write_bytes(
                _journal_with_gap(T0 * 1_000_000)
            )
            output = Path(directory) / "out"

            result = run_pipeline(root, output, year=2026)
            timeline = [
                json.loads(line)
                for line in (output / "timeline_full.jsonl").read_text().splitlines()
            ]
            view = artifact_view_for_timeline(output / "timeline_full.jsonl")

        self.assertEqual(result.errors, 0)
        by_action = {event["event_action"]: event for event in timeline}
        missing = by_action["lastlog_login_missing_from_wtmp"]
        self.assertEqual(missing["user"], "root")
        self.assertEqual(missing["source_type"], "integrity_check")
        self.assertTrue(missing["source_sha256"])
        self.assertEqual(
            sorted(missing["extra"]["derived_source_sha256s"]),
            ["var/log/lastlog", "var/log/wtmp"],
        )
        self.assertIn("journal_sequence_gap", by_action)
        integrity_rows = next(c for c in view["categories"] if c["id"] == "integrity")[
            "rows"
        ]
        self.assertIn(
            "notable",
            {row["score"] for row in integrity_rows if "lastlog" in row["cells"][1]},
        )


def _journal_with_gap(realtime_usec: int) -> bytes:
    builder = JournalBuilder()
    builder.message(
        realtime_usec, "Started nightly.service", SYSLOG_IDENTIFIER="systemd"
    )
    builder.entries += 5  # Sequence numbers written to a file that is not collected.
    builder.message(
        realtime_usec + 1_000_000,
        "Stopped nightly.service",
        SYSLOG_IDENTIFIER="systemd",
    )
    return builder.build()


if __name__ == "__main__":
    unittest.main()
