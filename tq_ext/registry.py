"""The two places where the upstream pipeline calls into this package."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from tq_ext.integrity import run_integrity_checks
from tq_ext.parsers import journal_binary, utmp
from uac_parser.timeline.event import TimelineEvent

Parser = Callable[..., list[TimelineEvent]]


def parsers() -> dict[str, Parser]:
    """Source types decoded by this package, keyed like ``PARSER_DISPATCH``."""
    return {
        "journal_binary": journal_binary.parse,
        "login_binary": utmp.parse,
    }


def post_parse(
    events: Sequence[TimelineEvent], sources: Sequence[Any], host: str = ""
) -> list[TimelineEvent]:
    """Derive additional events from one collection's parsed events.

    ``sources`` are the collection's discovered source files (objects with
    ``relative``, ``source_type``, ``size``, and ``event_count``). The returned
    events are appended to the collection; the input is never modified.
    """
    return run_integrity_checks(events, sources, host=host)
