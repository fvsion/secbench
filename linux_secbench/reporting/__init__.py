"""Report rendering in several formats from one precomputed bundle.

All renderers consume a single :class:`ReportBundle` (built once, analysis and
all) so a terminal summary, an HTML page, and a JSON export of the same scan
can never disagree with one another. Pick a renderer by name via
:func:`get_reporter`.
"""

from __future__ import annotations

from .base import ReportBundle, Reporter, build_bundle
from .terminal import TerminalReporter
from .html import HtmlReporter
from .json_report import JsonReporter
from .csv_report import CsvReporter
from .markdown import MarkdownReporter

#: Format name -> reporter class. The CLI's --format choices come from here.
REPORTERS = {
    "terminal": TerminalReporter,
    "html": HtmlReporter,
    "json": JsonReporter,
    "csv": CsvReporter,
    "markdown": MarkdownReporter,
}


def get_reporter(fmt: str) -> Reporter:
    try:
        return REPORTERS[fmt]()
    except KeyError as exc:
        raise ValueError(f"Unknown report format {fmt!r}; choose from {sorted(REPORTERS)}") from exc


__all__ = [
    "ReportBundle",
    "Reporter",
    "build_bundle",
    "TerminalReporter",
    "HtmlReporter",
    "JsonReporter",
    "CsvReporter",
    "MarkdownReporter",
    "REPORTERS",
    "get_reporter",
]
