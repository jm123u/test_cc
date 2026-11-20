"""HTTP routes served by the extension package.

The upstream handler calls :func:`handle_get` for paths it does not serve
itself. Every route is read-only (GET), so the upstream Host-header admission
check is the only gate required; no request here changes state.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tq_ext.artifact_view import artifact_view_for_timeline

WEB_ROOT = Path(__file__).resolve().parent / "web"
STATIC_FILES = {
    "/artifacts": ("artifact_view.html", "text/html; charset=utf-8"),
    "/ext/artifact_view.css": ("artifact_view.css", "text/css; charset=utf-8"),
    "/ext/artifact_view.js": ("artifact_view.js", "text/javascript; charset=utf-8"),
}
ARTIFACT_VIEW_ROUTE = re.compile(r"/api/job/([a-f0-9]{12})/artifact-view")
MAX_CACHED_VIEWS = 4

_cache: dict[tuple[str, int, int], bytes] = {}
_cache_lock = threading.Lock()


@dataclass(frozen=True)
class Response:
    status: int
    content_type: str
    body: bytes


def _json(payload: dict[str, Any], status: int = 200) -> Response:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    return Response(status, "application/json; charset=utf-8", body)


def _timeline_path(output_dir: Path) -> Path:
    for name in ("case_timeline_full.jsonl", "timeline_full.jsonl"):
        candidate = output_dir / name
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("Timeline output is unavailable for this job.")


def _artifact_view(job_id: str, job_output_dir: Callable[[str], Path]) -> Response:
    try:
        timeline = _timeline_path(job_output_dir(job_id))
    except FileNotFoundError as exc:
        return _json({"error": str(exc)}, status=404)
    stat = timeline.stat()
    key = (str(timeline), stat.st_mtime_ns, stat.st_size)
    with _cache_lock:
        cached = _cache.get(key)
    if cached is None:
        view = artifact_view_for_timeline(timeline)
        view["job_id"] = job_id
        cached = _json(view).body
        with _cache_lock:
            while len(_cache) >= MAX_CACHED_VIEWS:
                _cache.pop(next(iter(_cache)))
            _cache[key] = cached
    return Response(200, "application/json; charset=utf-8", cached)


def handle_get(path: str, job_output_dir: Callable[[str], Path]) -> Response | None:
    """Return a response for an extension route, or ``None`` if the path is not ours."""
    static = STATIC_FILES.get(path)
    if static is not None:
        name, content_type = static
        return Response(200, content_type, (WEB_ROOT / name).read_bytes())
    match = ARTIFACT_VIEW_ROUTE.fullmatch(path)
    if match:
        return _artifact_view(match.group(1), job_output_dir)
    return None
