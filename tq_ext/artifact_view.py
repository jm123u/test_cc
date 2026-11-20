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

MAX_ROWS_PER_CATEGORY = 2000
MAX_EVENTS_PER_ROW = 25
MAX_EVENTS_PER_GROUP = 5
MAX_GROUPS = 20000
OVERFLOW_GROUP = "(other sources)"
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
    """Rows for individual logons; failed attempts are tallied per source."""
    rows: list[Row] = []
    for event in events:
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
    return rows


class CappedBucket:
    """Hold a bounded sample of a category's events while counting all of them.

    Timelines can run to millions of events, so a category keeps at most
    ``limit`` flagged and ``limit`` unflagged events. Flagged events are kept
    in preference, and the totals stay exact.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.flagged: list[Event] = []
        self.plain: list[Event] = []
        self.total = 0
        self.scores = {NOTABLE: 0, LIKELY: 0}

    def add(self, event: Event) -> None:
        self.total += 1
        score = _score(event)
        if score:
            self.scores[score] += 1
            if len(self.flagged) < self.limit:
                self.flagged.append(event)
        elif len(self.plain) < self.limit:
            self.plain.append(event)

    def events(self) -> list[Event]:
        return self.flagged + self.plain


class GroupTally:
    """Count events per key, keeping a few sample events for each group."""

    def __init__(self) -> None:
        self.groups: dict[str, dict[str, Any]] = {}
        self.total = 0
        self.scores = {NOTABLE: 0, LIKELY: 0}

    def add(self, key: str, event: Event, value: str = "") -> None:
        self.total += 1
        score = _score(event)
        if score:
            self.scores[score] += 1
        group = self.groups.get(key)
        if group is None:
            if len(self.groups) >= MAX_GROUPS:
                key = OVERFLOW_GROUP
                group = self.groups.get(key)
            if group is None:
                group = {
                    "count": 0,
                    "first": "",
                    "last": "",
                    "values": {},
                    "kinds": {},
                    "events": [],
                    "flagged": 0,
                }
                self.groups[key] = group
        group["count"] += 1
        stamp = str(event.get("timestamp") or "")
        if stamp:
            group["first"] = min(group["first"] or stamp, stamp)
            group["last"] = max(group["last"], stamp)
        if value and len(group["values"]) < 8:
            group["values"][value] = True
        group["kinds"][str(event.get("source_type") or "")] = True
        events = group["events"]
        if score and group["flagged"] < MAX_EVENTS_PER_GROUP:
            group["flagged"] += 1
            if len(events) >= MAX_EVENTS_PER_GROUP:
                events.pop()
            events.insert(0, event)
        elif len(events) < MAX_EVENTS_PER_GROUP:
            events.append(event)

    @staticmethod
    def window(group: dict[str, Any]) -> str:
        first = group["first"][:19].replace("T", " ")
        last = group["last"][:19].replace("T", " ")
        if not first or first == last:
            return first
        return (
            f"{first} to {last[11:]}"
            if first[:10] == last[:10]
            else f"{first} to {last}"
        )

    def rows(self, cells: Callable[[str, dict[str, Any]], list[str]]) -> list[Row]:
        rows = []
        for key, group in self.groups.items():
            row = Row(
                [_text(cell) for cell in cells(key, group)], sort_key=group["first"]
            )
            row.events = list(group["events"])
            row.event_count = group["count"]
            rows.append(row)
        return rows


def _failed_logon_cells(source: str, group: dict[str, Any]) -> list[str]:
    users = list(group["values"])
    shown = ", ".join(users[:4]) + (" and others" if len(users) > 4 else "")
    count = group["count"]
    return [
        GroupTally.window(group),
        shown,
        source,
        f"Failed x {count}" if count > 1 else "Failed",
        ", ".join(sorted(kind for kind in group["kinds"] if kind)),
    ]


def _web_cells(client: str, group: dict[str, Any]) -> list[str]:
    sample = group["events"][0].get("summary") if group["events"] else ""
    return [client, str(group["count"]), GroupTally.window(group), _text(sample)]


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
        self.scores = {NOTABLE: 0, LIKELY: 0}

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
            self.scores[_score(event)] += 1
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
        lambda events: [],
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
    category: Category,
    rows: list[dict[str, Any]],
    event_count: int,
    scores: dict[str, int],
    omitted_rows: int,
    sampled: bool,
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
        "notable_events": scores[NOTABLE],
        "likely_events": scores[LIKELY],
        "truncated_rows": omitted_rows,
        "sampled": sampled,
    }


def _limit_rows(
    rows: list[dict[str, Any]], limit: int
) -> tuple[list[dict[str, Any]], int]:
    """Keep at most ``limit`` rows, preferring flagged rows, in sort order."""
    rows.sort(key=lambda row: row["sort"])
    omitted = max(0, len(rows) - limit)
    if omitted:
        flagged = [row for row in rows if row["score"]]
        plain = [row for row in rows if not row["score"]]
        rows = (flagged + plain)[:limit]
        rows.sort(key=lambda row: row["sort"])
    return rows, omitted


def build_artifact_view(events: Iterable[Event]) -> dict[str, Any]:
    """Classify events into categories in one pass with bounded memory.

    The first matching category wins. High-volume kinds (file timestamps,
    failed logons, web requests) are tallied instead of stored, and every
    other category keeps a bounded sample while its totals stay exact.
    """
    limit = MAX_ROWS_PER_CATEGORY
    buckets = {category.id: CappedBucket(limit) for category in (*CATEGORIES, OTHER)}
    hosts: dict[str, int] = {}
    files = FileActivity()
    failed_logons = GroupTally()
    web = GroupTally()
    total = 0
    for event in events:
        total += 1
        host = str(event.get("host") or "")
        if host:
            hosts[host] = hosts.get(host, 0) + 1
        action = event.get("event_action")
        if _integrity(event):
            buckets["integrity"].add(event)
        elif action in FILE_ACTIONS:
            files.add(event)
        elif action in FAILED_LOGON_ACTIONS:
            failed_logons.add(
                str(event.get("src_ip") or "(local)"),
                event,
                str(event.get("user") or "?"),
            )
        elif event.get("source_type") == "web_log":
            web.add(str(event.get("src_ip") or "(unknown)"), event)
        else:
            target = next((c.id for c in CATEGORIES if c.matches(event)), OTHER.id)
            buckets[target].add(event)
    by_id = {category.id: category for category in (*CATEGORIES, OTHER)}
    categories = []
    for category_id in DISPLAY_ORDER:
        category = by_id[category_id]
        bucket = buckets[category_id]
        scores = dict(bucket.scores)
        event_count = bucket.total
        sampled = bucket.total > len(bucket.flagged) + len(bucket.plain)
        if category_id == "files":
            rows, omitted = files.rows(limit)
            categories.append(
                _category_payload(
                    category, rows, files.event_count, files.scores, omitted, False
                )
            )
            continue
        built = category.build(bucket.events())
        tally = {"inbound": failed_logons, "web": web}.get(category_id)
        if tally is not None:
            built += tally.rows(
                _failed_logon_cells if category_id == "inbound" else _web_cells
            )
            event_count += tally.total
            for name in scores:
                scores[name] += tally.scores[name]
        rows, omitted = _limit_rows([_public_row(row) for row in built], limit)
        categories.append(
            _category_payload(category, rows, event_count, scores, omitted, sampled)
        )
    return {
        "schema": "tq_ext.artifact_view/1",
        "scoring": "severity",
        "event_count": total,
        "row_limit": limit,
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
