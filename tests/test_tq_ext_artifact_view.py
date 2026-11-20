from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tq_ext import web_routes
from tq_ext.artifact_view import MAX_EVENTS_PER_GROUP, build_artifact_view
from uac_parser.pipeline import run_pipeline


def event(**fields: object) -> dict[str, object]:
    base: dict[str, object] = {
        "event_id": "evt_x",
        "timestamp": "2026-03-01T09:15:00Z",
        "severity": "informational",
        "host": "web01",
        "summary": "",
        "raw": "",
        "source_path": "",
        "source_type": "",
        "event_action": "",
        "extra": {},
        "tags": [],
        "mitre": [],
        "detection_names": [],
    }
    base.update(fields)
    return base


def category(view: dict, category_id: str) -> dict:
    return next(item for item in view["categories"] if item["id"] == category_id)


class ArtifactViewTests(unittest.TestCase):
    def test_failed_logons_collapse_per_source_and_success_stays_visible(self) -> None:
        events = [
            event(
                event_action="ssh_login_failure",
                source_type="auth_log",
                user=f"user{index % 3}",
                src_ip="198.51.100.50",
                severity="low",
                timestamp=f"2026-03-01T09:{index:02d}:00Z",
            )
            for index in range(30)
        ]
        events.append(
            event(
                event_action="ssh_login_success",
                source_type="auth_log",
                user="root",
                src_ip="198.51.100.50",
                severity="high",
                summary="Successful SSH login for root from 198.51.100.50",
                timestamp="2026-03-01T09:31:00Z",
            )
        )

        inbound = category(build_artifact_view(events), "inbound")

        self.assertEqual(inbound["event_count"], 31)
        failed, success = inbound["rows"]
        self.assertEqual(failed["cells"][2:4], ["198.51.100.50", "Failed x 30"])
        self.assertEqual(failed["event_count"], 30)
        self.assertEqual(len(failed["events"]), MAX_EVENTS_PER_GROUP)
        self.assertEqual(failed["cells"][0], "2026-03-01 09:00:00 to 09:29:00")
        self.assertEqual(failed["cells"][1], "user0, user1, user2")
        self.assertEqual(failed["score"], "")
        self.assertEqual(success["cells"][3], "Success")
        self.assertEqual(success["score"], "notable")
        self.assertEqual(inbound["notable"], 1)
        self.assertEqual((inbound["notable_events"], inbound["likely_events"]), (1, 0))

    def test_accounts_merge_state_and_flag_changes(self) -> None:
        events = [
            event(
                source_type="passwd",
                event_action="account_observed",
                user="svc-backup",
                uid="1107",
                extra={"shell": "/bin/bash"},
            ),
            event(
                source_type="shadow",
                event_action="password_state_observed",
                user="svc-backup",
                timestamp="2026-02-28T00:00:00Z",
            ),
            event(
                source_type="account_diff",
                event_action="account_created_since_backup",
                user="svc-backup",
                severity="high",
                summary="Account created since backup: svc-backup",
            ),
            event(
                source_type="passwd",
                event_action="account_observed",
                user="root",
                uid="0",
            ),
        ]

        accounts = category(build_artifact_view(events), "accounts")

        self.assertEqual(
            [row["cells"][0] for row in accounts["rows"]], ["root", "svc-backup"]
        )
        flagged = accounts["rows"][1]
        self.assertEqual(flagged["cells"][1:4], ["1107", "/bin/bash", "2026-02-28"])
        self.assertEqual(flagged["score"], "notable")
        self.assertEqual(flagged["why"], ["Account created since backup: svc-backup"])
        self.assertEqual(flagged["events"][0]["severity"], "high")

    def test_category_routing_and_nothing_is_dropped(self) -> None:
        events = [
            event(
                event_action="shell_command",
                command="scp /tmp/a.tgz ops@203.0.113.9:/in/",
            ),
            event(
                event_action="shell_command",
                command="cat /etc/shadow",
                severity="medium",
            ),
            event(
                event_action="shell_command", command="history -c", mitre=["T1070.003"]
            ),
            event(
                event_action="listening_port",
                source_type="network_state",
                port="4444",
                process="run",
                pid="7",
                extra={"local_addr": "0.0.0.0"},
            ),
            event(
                event_action="outbound_connection",
                source_type="network_state",
                extra={
                    "local_endpoint": "10.0.0.5:5000",
                    "peer_endpoint": "203.0.113.9:443",
                },
            ),
            event(event_action="file_modified", file_path="/tmp/x", extra={"size": 10}),
            event(event_action="file_accessed", file_path="/tmp/x", extra={"size": 10}),
            event(
                event_action="login_records_zeroed",
                tags=["log_integrity"],
                severity="high",
            ),
            event(event_action="something_new", summary="unmapped"),
        ]

        view = build_artifact_view(events)
        counts = {item["id"]: item["event_count"] for item in view["categories"]}

        self.assertEqual(view["event_count"], len(events))
        self.assertEqual(sum(counts.values()), len(events))
        self.assertEqual(counts["outbound"], 1)
        self.assertEqual(counts["commands"], 1)
        self.assertEqual(counts["integrity"], 2)
        self.assertEqual(counts["ports"], 1)
        self.assertEqual(counts["connections"], 1)
        self.assertEqual(counts["other"], 1)
        self.assertEqual(
            category(view, "outbound")["rows"][0]["cells"][2:4], ["203.0.113.9", "scp"]
        )
        self.assertEqual(
            category(view, "ports")["rows"][0]["cells"], ["4444", "0.0.0.0", "run", "7"]
        )
        files = category(view, "files")
        self.assertEqual((len(files["rows"]), files["rows"][0]["event_count"]), (1, 2))
        self.assertEqual(files["event_count"], 2)
        self.assertEqual(
            files["rows"][0]["cells"],
            ["/tmp/x", "2026-03-01 09:15:00", "2026-03-01 09:15:00", "", "", "10", ""],
        )
        self.assertEqual(category(view, "commands")["likely"], 1)
        self.assertEqual(view["hosts"], ["web01"])

    def test_large_file_listings_stay_compact_and_keep_flagged_files(self) -> None:
        from tq_ext import artifact_view

        events = []
        for index in range(60):
            for action in (
                "file_modified",
                "file_accessed",
                "metadata_changed",
                "file_created",
            ):
                events.append(
                    event(
                        event_action=action,
                        file_path=f"/usr/lib/pkg/file_{index:03d}",
                        severity="high"
                        if index == 57 and action == "file_modified"
                        else "informational",
                        summary=f"{action} file_{index:03d}",
                        raw=f"0|/usr/lib/pkg/file_{index:03d}|...",
                        source_path="bodyfile/bodyfile.txt",
                    )
                )
        original = artifact_view.MAX_ROWS_PER_CATEGORY
        artifact_view.MAX_ROWS_PER_CATEGORY = 10
        try:
            view = build_artifact_view(events)
        finally:
            artifact_view.MAX_ROWS_PER_CATEGORY = original

        files = category(view, "files")
        self.assertEqual(files["event_count"], 240)
        self.assertEqual((len(files["rows"]), files["truncated_rows"]), (10, 50))
        flagged = [row for row in files["rows"] if row["score"]]
        self.assertEqual(
            [row["cells"][0] for row in flagged], ["/usr/lib/pkg/file_057"]
        )
        self.assertEqual(flagged[0]["why"], ["file_modified file_057"])
        self.assertEqual(flagged[0]["event_count"], 4)
        plain = files["rows"][0]
        self.assertEqual(plain["events"][0]["raw"], "0|/usr/lib/pkg/file_000|...")
        self.assertEqual(category(view, "other")["event_count"], 0)

    def test_high_volume_categories_are_sampled_with_exact_totals(self) -> None:
        from tq_ext import artifact_view

        events = [
            event(
                event_action="shell_command",
                command=f"ls /srv/{index}",
                severity="high" if index % 100 == 0 else "informational",
                summary=f"Shell command {index}",
                timestamp=f"2026-03-01T{index // 3600:02d}:{index // 60 % 60:02d}:{index % 60:02d}Z",
            )
            for index in range(3000)
        ]
        events += [
            event(
                source_type="web_log",
                event_action="http_request",
                src_ip=f"203.0.113.{index % 7}",
                summary=f"GET /item/{index} returned 200",
                severity="medium" if index == 4000 else "informational",
            )
            for index in range(5000)
        ]
        original = artifact_view.MAX_ROWS_PER_CATEGORY
        artifact_view.MAX_ROWS_PER_CATEGORY = 50
        try:
            view = build_artifact_view(events)
        finally:
            artifact_view.MAX_ROWS_PER_CATEGORY = original

        commands = category(view, "commands")
        self.assertEqual(commands["event_count"], 3000)
        self.assertEqual(commands["notable_events"], 30)
        self.assertTrue(commands["sampled"])
        self.assertEqual(len(commands["rows"]), 50)
        self.assertEqual(sum(row["score"] == "notable" for row in commands["rows"]), 30)
        web = category(view, "web")
        self.assertEqual((web["event_count"], len(web["rows"])), (5000, 7))
        self.assertEqual(sum(int(row["cells"][1]) for row in web["rows"]), 5000)
        self.assertEqual(web["likely_events"], 1)
        flagged = [row for row in web["rows"] if row["score"]]
        self.assertEqual(
            flagged[0]["events"][0]["summary"], "GET /item/4000 returned 200"
        )
        self.assertEqual(view["row_limit"], 50)

    def test_routes_serve_page_assets_and_job_view(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "collection"
            (root / "var/log").mkdir(parents=True)
            (root / "var/log/auth.log").write_text(
                "Jun 16 10:00:01 host sshd[7]: Accepted password for root "
                "from 198.51.100.8 port 4242 ssh2\n",
                encoding="utf-8",
            )
            output = Path(directory) / "out"
            run_pipeline(root, output, year=2026)

            def output_dir(job_id: str) -> Path:
                if job_id != "a" * 12:
                    raise FileNotFoundError("Completed job not found.")
                return output

            page = web_routes.handle_get("/artifacts", output_dir)
            script = web_routes.handle_get("/ext/artifact_view.js", output_dir)
            found = web_routes.handle_get(
                f"/api/job/{'a' * 12}/artifact-view", output_dir
            )
            again = web_routes.handle_get(
                f"/api/job/{'a' * 12}/artifact-view", output_dir
            )
            missing = web_routes.handle_get(
                f"/api/job/{'b' * 12}/artifact-view", output_dir
            )

        assert page and script and found and again and missing
        self.assertIn(b"/ext/artifact_view.js", page.body)
        self.assertNotIn(b"<style", page.body)
        self.assertNotIn(b"<script>", page.body)
        self.assertEqual(script.content_type, "text/javascript; charset=utf-8")
        view = json.loads(found.body)
        self.assertEqual(view["job_id"], "a" * 12)
        self.assertEqual(
            category(view, "inbound")["rows"][0]["cells"][1:4],
            ["root", "198.51.100.8", "Success"],
        )
        self.assertEqual(found.body, again.body)
        self.assertEqual(missing.status, 404)
        self.assertIsNone(web_routes.handle_get("/ext/../web.py", output_dir))
        self.assertIsNone(
            web_routes.handle_get("/api/job/not-a-job/artifact-view", output_dir)
        )


if __name__ == "__main__":
    unittest.main()
