"""Minimal ANSI styling — no third-party dependency.

Honours the ``NO_COLOR`` convention and auto-disables when stdout is not a TTY,
so piping the report to a file or a pager yields clean text. Everything degrades
to plain strings when colour is off, so call sites never branch.
"""

from __future__ import annotations

import os
import sys

_CODES = {
    "reset": "0", "bold": "1", "dim": "2", "italic": "3", "underline": "4",
    "black": "30", "red": "31", "green": "32", "yellow": "33",
    "blue": "34", "magenta": "35", "cyan": "36", "white": "37", "gray": "90",
    "bright_red": "91", "bright_green": "92", "bright_yellow": "93",
    "bright_blue": "94", "bright_magenta": "95", "bright_cyan": "96",
    "bg_red": "41", "bg_green": "42", "bg_yellow": "43", "bg_blue": "44",
}


class Style:
    """A small stylesheet object; instantiate once with the desired enabled state."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def paint(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        codes = ";".join(_CODES[s] for s in styles if s in _CODES)
        if not codes:
            return text
        return f"\033[{codes}m{text}\033[0m"

    # Convenience shortcuts used throughout the terminal reporter.
    def bold(self, t: str) -> str: return self.paint(t, "bold")
    def dim(self, t: str) -> str: return self.paint(t, "dim")
    def red(self, t: str) -> str: return self.paint(t, "red")
    def green(self, t: str) -> str: return self.paint(t, "green")
    def yellow(self, t: str) -> str: return self.paint(t, "yellow")
    def cyan(self, t: str) -> str: return self.paint(t, "cyan")
    def gray(self, t: str) -> str: return self.paint(t, "gray")


def should_colorize(stream=None, override=None) -> bool:
    """Decide whether to emit colour for ``stream`` (default stdout).

    Precedence: explicit override → NO_COLOR env (disables) → FORCE_COLOR env
    (enables) → is-a-tty. This is the single source of truth so the CLI and the
    reporter never disagree.
    """
    if override is not None:
        return override
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    stream = stream or sys.stdout
    try:
        return bool(stream.isatty())
    except Exception:  # pragma: no cover - defensive
        return False


def visible_len(text: str) -> int:
    """Length of ``text`` ignoring ANSI escape sequences (for alignment)."""
    out, i = 0, 0
    while i < len(text):
        if text[i] == "\033":
            while i < len(text) and text[i] != "m":
                i += 1
            i += 1
        else:
            out += 1
            i += 1
    return out
