# tq_ext

Extensions kept separate from the upstream `uac_parser` package so upstream
releases can be merged with little friction.

## What is here

| Module | Purpose |
| --- | --- |
| `parsers/utmp.py` | Native `wtmp`, `btmp`, `utmp`, and `lastlog` decoder. |
| `parsers/journal_binary.py` | Native systemd `*.journal` decoder. |
| `integrity.py` | Cross-source log integrity checks (see below). |
| `artifact_view.py` | Groups a parsed timeline by artifact category for triage. |
| `web_routes.py` | Read-only HTTP routes: the `/artifacts` page, its assets, and `/api/job/<id>/artifact-view`. |
| `registry.py` | The functions the upstream pipeline calls. |
| `web/` | The artifact view page. |

## Touchpoints in upstream code

Only these upstream lines know that this package exists. Re-check them after
merging a new upstream release.

| # | File | Change |
| --- | --- | --- |
| 1 | `uac_parser/pipeline.py` | `PARSER_DISPATCH.update(extension_parsers())` registers the decoders. |
| 1 | `uac_parser/loaders/uac_layout.py` | Wider file-name patterns for `login_binary` (rotations, `utmp`) and a rule that keeps text exports out of it. |
| 2 | `uac_parser/pipeline.py` | `_extension_events` passes one collection's parsed events to `tq_ext.registry.post_parse` and appends what it returns. |
| 3 | `uac_parser/web.py` | `do_GET` calls `_handle_extension_get`, which forwards unknown GET paths to `tq_ext.web_routes.handle_get`. |
| 3 | `web/index.html`, `web/app.js` | One `Artifact View` link in the run actions and the line that sets its `href`. |

Smaller edits: `uac_parser/assist.py` and `web/app.js` list `login_binary` as
an authentication source, and `rules/attack_phases.yml` registers `T1070.002`.
Packaging (`pyproject.toml`, `Dockerfile`, `packaging/windows/build_portable.py`)
lists the package so it ships with the application.

## Integrity checks

Each check compares independent records of the same activity and stays silent
when it cannot judge.

| Finding | Compares | Severity | Not judged when |
| --- | --- | --- | --- |
| `lastlog_login_missing_from_wtmp` | lastlog entry vs wtmp login within 120 s | high | the entry is older than the collected wtmp history |
| `wtmp_empty_with_lastlog_records` | lastlog entries vs an empty wtmp | medium | no wtmp file was collected |
| `wtmp_login_missing_from_auth_log` | remote wtmp login vs auth log or journal auth entries within 300 s | high | the login is outside the auth log's time range |
| `wtmp_and_auth_log_disagree_systematically` | same, when most logins mismatch | low | fewer than three mismatches; points at a wrong timezone setting |
| `log_gap_while_host_active` / `log_gap` | silence in syslog, journal, or auditd vs its typical spacing | medium / low | fewer than 200 entries, or a boot or shutdown explains the gap |
| `journal_sequence_gap` | journal sequence numbers across collected files | low | no gaps |

## Scoring

The first version derives the score from the parser severity: `critical` and
`high` are Notable, `medium` is Likely notable. The category rules live in
`CATEGORIES` in `artifact_view.py`; the first matching category wins and
unmatched events are listed under Other Events, so nothing is hidden.
