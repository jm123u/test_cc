# tq_ext

Extensions kept separate from the upstream `uac_parser` package so upstream
releases can be merged with little friction.

## What is here

| Module | Purpose |
| --- | --- |
| `artifact_view.py` | Groups a parsed timeline by artifact category (accounts, logons, commands, processes, ports, persistence, log integrity) for triage. |
| `web_routes.py` | Read-only HTTP routes: the `/artifacts` page, its assets, and `/api/job/<id>/artifact-view`. |
| `web/` | The artifact view page. |

## Touchpoints in upstream code

Only these upstream lines know that this package exists. Re-check them after
merging a new upstream release.

| File | Change |
| --- | --- |
| `uac_parser/web.py` | `do_GET` calls `_handle_extension_get`, which forwards unknown GET paths to `tq_ext.web_routes.handle_get`. |
| `web/index.html` | One `Artifact View` link in the run actions. |
| `web/app.js` | Sets that link's `href` when a job completes. |

Packaging (`pyproject.toml`, `Dockerfile`, `packaging/windows/build_portable.py`)
also lists the package so it ships with the application.

## Scoring

The first version derives the score from the parser severity: `critical` and
`high` are Notable, `medium` is Likely notable. The category rules live in
`CATEGORIES` in `artifact_view.py`; the first matching category wins and
unmatched events are listed under Other Events, so nothing is hidden.
