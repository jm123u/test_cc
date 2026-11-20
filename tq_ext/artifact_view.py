"""Group a parsed timeline by artifact category for triage.

The timeline answers "what happened next"; this view answers "what on this
host stands out". It reads the JSONL timeline TraceQuarry already wrote and
never changes it. Nothing is dropped: events that match no category land in
``Other Events``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

Event = dict[str, Any]

NOTABLE = "notable"
LIKELY = "likely"
NONE = ""
SCORE_RANK = {NOTABLE: 2, LIKELY: 1, NONE: 0}
# First version: derive the score from the upstream severity label.
SEVERITY_SCORE = {"critical": NOTABLE, "high": NOTABLE, "medium": LIKELY}

MAX_ROWS_PER_CATEGORY = 5000
MAX_EVENTS_PER_ROW = 25
MAX_TEXT = 2000

REMOTE_COMMAND_RE = re.compile(
    r"(?:^|[;&|]\s*|\bsudo\s+)(?P<tool>ssh|scp|sftp|rsync)\s+(?P<rest>[^;&|]*)"
)
REMOTE_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*|\[[0-9A-Fa-f:]+\]")
INTERACTIVE_REMOTE_TOOLS = {"ssh", "sftp"}

LOGON_ACTIONS = {
    "ssh_login_success",
    "ssh_login_failure",
    "login_session",
    "login_failed",
    "last_login_record",
    "logout_session",
}
FAILED_LOGON_ACTIONS = {"ssh_login_failure", "login_failed"}
ACCOUNT_SOURCES = {"passwd", "shadow", "group", "account_diff"}
ACCOUNT_ACTIONS = {
    "user_created",
    "user_deleted",
    "password_changed",
    "account_locked",
    "account_unlocked",
    "group_member_added",
}
TASK_SOURCES = {"cron", "cron_file", "systemd", "systemd_unit"}
CONFIG_SOURCES = {
    "ld_preload",
    "pam_config",
    "profile",
    "rc_local",
    "sshd_config",
    "sudoers",
    "capabilities",
    "bodyfile_privilege",
}
COMMAND_ACTIONS = {
    "shell_command",
    "process_execution",
    "sudo_command",
    "su_session_opened",
}
FILE_ACTIONS = {
    "file_modified": 0,
    "file_accessed": 1,
    "metadata_changed": 2,
    "file_created": 3,
}
MAX_FLAGGED_EVENTS_PER_FILE = 4
INTEGRITY_ACTIONS = {
    "login_records_zeroed",
    "login_record_time_regression",
    "login_database_truncated",
    "login_database_anomalies_suppressed",
    "login_database_partially_read",
    "journal_partially_decoded",
    "system_time_change",
}


@dataclass
class Row:
    cells: list[str]
    sort_key: str = ""
    events: list[Event] = field(default_factory=list)
    event_count: int = 0

    def add(self, event: Event) -> None:
        self.event_count += 1
        if len(self.events) < MAX_EVENTS_PER_ROW:
            self.events.append(event)
        elif _score(event) != NONE and _score(self.events[-1]) == NONE:
            # Keep flagged evidence visible even in a very long group.
            self.events[-1] = event


@dataclass(frozen=True)
class Category:
    id: str
    group: str
    name: str
    description: str
    columns: tuple[str, ...]
    mono: tuple[int, ...]
    matches: Callable[[Event], bool]
    build: Callable[[list[Event]], list[Row]]


def _text(value: object) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT] + " [truncated]"


def _time(event: Event) -> str:
    stamp = str(event.get("timestamp") or "")
    return stamp[:19].replace("T", " ") if stamp else ""


def _score(event: Event) -> str:
    return SEVERITY_SCORE.get(str(event.get("severity") or "").lower(), NONE)


def _extra(event: Event, key: str) -> str:
    extra = event.get("extra")
    return (
        _text(extra.get(key))
        if isinstance(extra, dict) and extra.get(key) is not None
        else ""
    )


def _span(events: list[Event]) -> str:
    stamps = sorted(_time(event) for event in events if event.get("timestamp"))
    if not stamps:
        return ""
    return (
        stamps[0]
        if stamps[0] == stamps[-1]
        else f"{stamps[0]} to {stamps[-1][11:]}"
        if stamps[0][:10] == stamps[-1][:10]
        else f"{stamps[0]} to {stamps[-1]}"
    )


def _simple(
    cells: Callable[[Event], Sequence[object]],
) -> Callable[[list[Event]], list[Row]]:
    def build(events: list[Event]) -> list[Row]:
        rows = []
        for event in events:
            row = Row(
                [_text(cell) for cell in cells(event)],
                sort_key=str(event.get("timestamp") or ""),
            )
            row.add(event)
            rows.append(row)
        return rows

    return build


def _grouped(
    key: Callable[[Event], str], cells: Callable[[str, list[Event]], Sequence[object]]
) -> Callable[[list[Event]], list[Row]]:
    def build(events: list[Event]) -> list[Row]:
        groups: dict[str, list[Event]] = {}
        for event in events:
            groups.setdefault(key(event), []).append(event)
        rows = []
        for name, members in groups.items():
            stamps = sorted(
                str(e.get("timestamp") or "") for e in members if e.get("timestamp")
            )
            row = Row(
                [_text(cell) for cell in cells(name, members)],
                sort_key=stamps[0] if stamps else "",
            )
            for member in sorted(members, key=lambda e: -SCORE_RANK[_score(e)]):
                row.add(member)
            rows.append(row)
        return rows

    return build


# --- category builders -----------------------------------------------------


def _build_accounts(events: list[Event]) -> list[Row]:
    accounts: dict[str, dict[str, Any]] = {}
    loose: list[Event] = []
    for event in events:
        user = str(event.get("user") or "")
        if not user:
            if _score(event) != NONE:
                loose.append(event)
            continue
        entry = accounts.setdefault(
            user, {"uid": "", "shell": "", "pw_changed": "", "events": []}
        )
        entry["events"].append(event)
        entry["uid"] = entry["uid"] or str(event.get("uid") or "")
        entry["shell"] = entry["shell"] or _extra(event, "shell")
        if event.get("event_action") == "password_state_observed" and event.get(
            "timestamp"
        ):
            entry["pw_changed"] = str(event["timestamp"])[:10]
    rows = []
    for user, entry in accounts.items():
        flagged = [e for e in entry["events"] if _score(e) != NONE]
        notes = "; ".join(dict.fromkeys(_text(e.get("summary")) for e in flagged))
        row = Row(
            [user, entry["uid"], entry["shell"], entry["pw_changed"], notes],
            sort_key=f"{int(entry['uid']):010d}"
            if entry["uid"].isdigit()
            else f"z{user}",
        )
        for event in sorted(entry["events"], key=lambda e: -SCORE_RANK[_score(e)]):
            row.add(event)
        rows.append(row)
    for event in loose:
        row = Row(["(group)", "", "", "", _text(event.get("summary"))], sort_key="zz")
        row.add(event)
        rows.append(row)
    return rows


def _logon_result(event: Event) -> str:
    action = event.get("event_action")
    if action in FAILED_LOGON_ACTIONS:
        return "Failed"
    if action == "logout_session":
        return "Logout"
    if action == "last_login_record":
        return "Last login (lastlog)"
    return "Success"


def _build_inbound(events: list[Event]) -> list[Row]:
    rows: list[Row] = []
    failures: dict[str, list[Event]] = {}
    for event in events:
        if event.get("event_action") in FAILED_LOGON_ACTIONS:
            failures.setdefault(str(event.get("src_ip") or "(local)"), []).append(event)
            continue
        row = Row(
            [
                _time(event),
                _text(event.get("user")),
                _text(event.get("src_ip") or _extra(event, "remote_host") or "local"),
                _logon_result(event),
                _text(event.get("source_type")),
            ],
            sort_key=str(event.get("timestamp") or ""),
        )
        row.add(event)
        rows.append(row)
    for source, members in failures.items():
        users = list(dict.fromkeys(str(e.get("user") or "?") for e in members))
        shown = ", ".join(users[:4]) + (
            f" +{len(users) - 4} more" if len(users) > 4 else ""
        )
        stamps = sorted(
            str(e.get("timestamp") or "") for e in members if e.get("timestamp")
        )
        row = Row(
            [
                _span(members),
                shown,
                source,
                f"Failed x {len(members)}" if len(members) > 1 else "Failed",
                ", ".join(sorted({str(e.get("source_type") or "") for e in members})),
            ],
            sort_key=stamps[0] if stamps else "",
        )
        for member in sorted(members, key=lambda e: -SCORE_RANK[_score(e)]):
            row.add(member)
        rows.append(row)
    return rows


def _remote_host(tool: str, arguments: str) -> str:
    """Pick the remote host out of an ssh/scp/sftp/rsync argument list."""
    plain = ""
    for token in arguments.split():
        if token.startswith(("-", "/", ".", "~")):
            continue
        if "@" in token:
            host = token.split("@", 1)[1].split(":", 1)[0]
            if REMOTE_HOST_RE.fullmatch(host):
                return host
        elif ":" in token:
            host = token.split(":", 1)[0]
            if REMOTE_HOST_RE.fullmatch(host):
                return host
        elif (
            not plain
            and tool in INTERACTIVE_REMOTE_TOOLS
            and REMOTE_HOST_RE.fullmatch(token)
        ):
            plain = token
    return plain


def _remote_target(event: Event) -> tuple[str, str] | None:
    if event.get("event_action") == "known_host_observed":
        return "known_hosts", _text(event.get("dst_ip") or event.get("summary"))
    if event.get("event_action") not in COMMAND_ACTIONS:
        return None
    match = REMOTE_COMMAND_RE.search(str(event.get("command") or ""))
    if not match:
        return None
    return match.group("tool"), _remote_host(match.group("tool"), match.group("rest"))


def _is_outbound(event: Event) -> bool:
    return _remote_target(event) is not None


def _outbound_cells(event: Event) -> list[str]:
    tool, target = _remote_target(event) or ("", "")
    return [
        _time(event),
        _text(event.get("user")),
        target,
        tool,
        _text(event.get("command") or event.get("file_path")),
    ]


class FileActivity:
    """Fold file-timestamp events into one compact record per path.

    A file listing contributes up to four events per file and can run to
    millions of events, so this keeps a few strings per path instead of the
    events themselves. Only flagged events are retained for the detail view.
    """

    def __init__(self) -> None:
        self.files: dict[str, list[Any]] = {}
        self.event_count = 0

    def add(self, event: Event) -> None:
        self.event_count += 1
        path = str(event.get("file_path") or "")
        record = self.files.get(path)
        if record is None:
            # times[4], size, uid, raw, source_path, event_count, flagged events
            record = [
                ["", "", "", ""],
                _extra(event, "size"),
                _text(event.get("uid")),
                _text(event.get("raw")),
                _text(event.get("source_path")),
                0,
                None,
            ]
            self.files[path] = record
        slot = FILE_ACTIONS[str(event.get("event_action"))]
        record[0][slot] = max(record[0][slot], _time(event))
        record[5] += 1
        if _score(event) != NONE:
            if record[6] is None:
                record[6] = []
            if len(record[6]) < MAX_FLAGGED_EVENTS_PER_FILE:
                record[6].append(_public_event(event))

    def rows(self, limit: int) -> tuple[list[dict[str, Any]], int]:
        flagged = sorted(path for path, record in self.files.items() if record[6])
        room = max(0, limit - len(flagged))
        plain = sorted(path for path, record in self.files.items() if not record[6])
        chosen = sorted(flagged[:limit] + plain[:room])
        rows = []
        for path in chosen:
            times, size, uid, raw, source_path, count, events = self.files[path]
            events = events or []
            score = max(
                (event["score"] for event in events),
                key=lambda s: SCORE_RANK[s],
                default=NONE,
            )
            rows.append(
                {
                    "cells": [_text(path), *times, size, uid],
                    "score": score,
                    "why": list(dict.fromkeys(event["summary"] for event in events)),
                    "event_count": count,
                    "events": events
                    or [
                        {
                            "event_id": "",
                            "timestamp": max(times),
                            "severity": "informational",
                            "score": NONE,
                            "summary": f"File timestamps for {_text(path)}",
                            "raw": raw,
                            "source_path": source_path,
                            "source_type": "bodyfile",
                            "host": "",
                            "detections": "",
                            "mitre": "",
                        }
                    ],
                    "sort": path,
                }
            )
        return rows, len(self.files) - len(chosen)


def _connection_cells(event: Event) -> list[str]:
    local = _extra(event, "local_endpoint") or _text(event.get("src_ip"))
    peer = _extra(event, "peer_endpoint") or ":".join(
        part for part in (_text(event.get("dst_ip")), _text(event.get("port"))) if part
    )
    process = _text(event.get("process"))
    pid = _text(event.get("pid"))
    return [
        local,
        peer,
        _extra(event, "state"),
        _extra(event, "direction"),
        f"{process} ({pid})" if pid else process,
    ]


def _integrity(event: Event) -> bool:
    tags = event.get("tags") or []
    mitre = event.get("mitre") or []
    return (
        event.get("event_action") in INTEGRITY_ACTIONS
        or "log_integrity" in tags
        or any(str(technique).startswith("T1070") for technique in mitre)
    )


CATEGORIES: tuple[Category, ...] = (
    Category(
        "integrity",
        "System",
        "Log Integrity",
        "Signs that logs were altered, cleared, truncated, or only partly readable.",
        ("Time (UTC)", "Finding", "Source"),
        (2,),
        _integrity,
        _simple(lambda e: [_time(e), e.get("summary"), e.get("source_path")]),
    ),
    Category(
        "accounts",
        "User",
        "Accounts",
        "Local accounts with their state, changes since backup copies, and account activity.",
        ("User", "UID", "Shell", "Password changed", "Flagged changes"),
        (2,),
        lambda e: (
            e.get("source_type") in ACCOUNT_SOURCES
            or e.get("event_action") in ACCOUNT_ACTIONS
        ),
        _build_accounts,
    ),
    Category(
        "inbound",
        "User",
        "Inbound Logons",
        "Logons to this host. Failed attempts are combined per source address.",
        ("Time (UTC)", "User", "Source", "Result", "Evidence"),
        (2,),
        lambda e: e.get("event_action") in LOGON_ACTIONS,
        _build_inbound,
    ),
    Category(
        "outbound",
        "User",
        "Outbound Logons",
        "Remote sessions and copies started from this host, and hosts it has connected to.",
        ("Time (UTC)", "User", "Destination", "Tool", "Detail"),
        (2, 4),
        _is_outbound,
        _simple(_outbound_cells),
    ),
    Category(
        "commands",
        "User",
        "Commands",
        "Commands from shell history, audit records, and sudo.",
        ("Time (UTC)", "User", "Command", "Evidence"),
        (2,),
        lambda e: e.get("event_action") in COMMAND_ACTIONS,
        _simple(
            lambda e: [
                _time(e),
                e.get("user"),
                e.get("command") or e.get("summary"),
                e.get("source_type"),
            ]
        ),
    ),
    Category(
        "files",
        "User",
        "File Activity",
        "Files with recorded timestamps, one row per path, ordered by path.",
        ("Path", "Modified", "Accessed", "Changed", "Created", "Size", "UID"),
        (0,),
        lambda e: e.get("event_action") in FILE_ACTIONS,
        lambda events: [],
    ),
    Category(
        "processes",
        "Process",
        "Processes",
        "Processes running when the collection was taken.",
        ("PID", "User", "Command", "Time (UTC)"),
        (2,),
        lambda e: e.get("event_action") == "process_running",
        _simple(
            lambda e: [
                e.get("pid"),
                e.get("user"),
                e.get("command") or e.get("process"),
                _time(e),
            ]
        ),
    ),
    Category(
        "tasks",
        "Process",
        "Scheduled Tasks",
        "Cron entries, systemd services, and timers.",
        ("Defined in", "Command", "Kind", "Time (UTC)"),
        (0, 1),
        lambda e: e.get("source_type") in TASK_SOURCES,
        _simple(
            lambda e: [
                e.get("file_path") or e.get("source_path"),
                e.get("command") or e.get("summary"),
                e.get("source_type"),
                _time(e),
            ]
        ),
    ),
    Category(
        "ports",
        "Network",
        "Listening Ports",
        "Ports this host had open for incoming connections.",
        ("Port", "Address", "Process", "PID"),
        (1,),
        lambda e: e.get("event_action") == "listening_port",
        _simple(
            lambda e: [
                e.get("port"),
                _extra(e, "local_addr"),
                e.get("process"),
                e.get("pid"),
            ]
        ),
    ),
    Category(
        "connections",
        "Network",
        "Connections",
        "Sockets that were open when the collection was taken.",
        ("Local", "Remote", "State", "Direction", "Process"),
        (0, 1),
        lambda e: e.get("source_type") == "network_state",
        _simple(_connection_cells),
    ),
    Category(
        "web",
        "Network",
        "Web Requests",
        "Requests recorded by web servers on this host, combined per client address.",
        ("Client", "Requests", "Window (UTC)", "Sample"),
        (0, 3),
        lambda e: e.get("source_type") == "web_log",
        _grouped(
            lambda e: str(e.get("src_ip") or "(unknown)"),
            lambda client, members: [
                client,
                str(len(members)),
                _span(members),
                _text(members[0].get("summary")),
            ],
        ),
    ),
    Category(
        "keys",
        "Persistence",
        "SSH Keys",
        "Keys allowed to log in to each account.",
        ("File", "Key type", "Comment", "Time (UTC)"),
        (0,),
        lambda e: e.get("source_type") == "authorized_keys",
        _simple(
            lambda e: [
                e.get("file_path"),
                _extra(e, "key_type"),
                _extra(e, "comment"),
                _time(e),
            ]
        ),
    ),
    Category(
        "config",
        "Persistence",
        "Config and PAM",
        "Preload entries, PAM modules, shell profiles, sudoers rules, and SSH server settings.",
        ("File", "Entry", "Kind"),
        (0, 1),
        lambda e: e.get("source_type") in CONFIG_SOURCES,
        _simple(
            lambda e: [
                e.get("file_path") or e.get("source_path"),
                e.get("command") or e.get("summary"),
                e.get("source_type"),
            ]
        ),
    ),
)
OTHER = Category(
    "other",
    "System",
    "Other Events",
    "Parsed events that fit none of the categories above. Nothing is hidden from this view.",
    ("Time (UTC)", "Summary", "Kind", "Evidence"),
    (),
    lambda e: True,
    _simple(
        lambda e: [
            _time(e),
            e.get("summary"),
            e.get("event_action"),
            e.get("source_type"),
        ]
    ),
)
DISPLAY_ORDER = (
    "accounts",
    "inbound",
    "outbound",
    "commands",
    "files",
    "processes",
    "tasks",
    "ports",
    "connections",
    "web",
    "keys",
    "config",
    "integrity",
    "other",
)


def _public_event(event: Event) -> dict[str, str]:
    return {
        "event_id": _text(event.get("event_id")),
        "timestamp": _text(event.get("timestamp")),
        "severity": _text(event.get("severity")),
        "score": _score(event),
        "summary": _text(event.get("summary")),
        "raw": _text(event.get("raw")),
        "source_path": _text(event.get("source_path")),
        "source_type": _text(event.get("source_type")),
        "host": _text(event.get("host")),
        "detections": ", ".join(
            str(name) for name in (event.get("detection_names") or [])
        ),
        "mitre": ", ".join(str(name) for name in (event.get("mitre") or [])),
    }


def _public_row(row: Row) -> dict[str, Any]:
    score = max(
        (_score(event) for event in row.events),
        key=lambda s: SCORE_RANK[s],
        default=NONE,
    )
    flagged = [event for event in row.events if _score(event) != NONE]
    why = list(dict.fromkeys(_text(event.get("summary")) for event in flagged))[:6]
    return {
        "cells": row.cells,
        "score": score,
        "why": why,
        "event_count": row.event_count,
        "events": [_public_event(event) for event in row.events],
        "sort": row.sort_key,
    }


def _category_payload(
    category: Category, rows: list[dict[str, Any]], event_count: int, truncated: int
) -> dict[str, Any]:
    return {
        "id": category.id,
        "group": category.group,
        "name": category.name,
        "description": category.description,
        "columns": list(category.columns),
        "mono": list(category.mono),
        "rows": rows,
        "event_count": event_count,
        "notable": sum(row["score"] == NOTABLE for row in rows),
        "likely": sum(row["score"] == LIKELY for row in rows),
        "truncated_rows": truncated,
    }


def build_artifact_view(events: Iterable[Event]) -> dict[str, Any]:
    """Classify events into categories; the first matching category wins."""
    buckets: dict[str, list[Event]] = {category.id: [] for category in CATEGORIES}
    buckets[OTHER.id] = []
    hosts: dict[str, int] = {}
    files = FileActivity()
    total = 0
    for event in events:
        total += 1
        host = str(event.get("host") or "")
        if host:
            hosts[host] = hosts.get(host, 0) + 1
        if event.get("event_action") in FILE_ACTIONS and not _integrity(event):
            files.add(event)
            continue
        target = next((c.id for c in CATEGORIES if c.matches(event)), OTHER.id)
        buckets[target].append(event)
    by_id = {category.id: category for category in (*CATEGORIES, OTHER)}
    categories = []
    for category_id in DISPLAY_ORDER:
        category = by_id[category_id]
        if category_id == "files":
            rows, truncated = files.rows(MAX_ROWS_PER_CATEGORY)
            categories.append(
                _category_payload(category, rows, files.event_count, truncated)
            )
            continue
        rows = [_public_row(row) for row in category.build(buckets[category_id])]
        rows.sort(key=lambda row: row["sort"])
        truncated = max(0, len(rows) - MAX_ROWS_PER_CATEGORY)
        if truncated:
            flagged_rows = [row for row in rows if row["score"]]
            rest = [row for row in rows if not row["score"]]
            rows = (flagged_rows + rest)[:MAX_ROWS_PER_CATEGORY]
            rows.sort(key=lambda row: row["sort"])
        categories.append(
            _category_payload(category, rows, len(buckets[category_id]), truncated)
        )
    return {
        "schema": "tq_ext.artifact_view/1",
        "scoring": "severity",
        "event_count": total,
        "hosts": sorted(hosts, key=lambda name: -hosts[name]),
        "categories": categories,
    }


def read_timeline(path: Path) -> Iterable[Event]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                yield event


def artifact_view_for_timeline(path: Path) -> dict[str, Any]:
    return build_artifact_view(read_timeline(path))
