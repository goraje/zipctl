"""Glob-pattern-to-regex translation used by :class:`zipctl.zipfile.path.Path`.

Adapted from CPython's ``zipfile._path.glob`` module.  Only ``/`` is treated
as a path separator so that translated patterns behave consistently across
platforms when matched against POSIX-style archive member names.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator
from re import Match

__all__ = ["Translator"]

_seps = "/"


class Translator:
    """Translate shell-style glob patterns into regular expressions.

    Only ``/`` is recognized as a path separator, matching the POSIX-style
    names stored in ZIP archives.
    """

    seps: str

    def __init__(self, seps: str = _seps) -> None:
        """Create a translator using *seps* as the path separator characters.

        Args:
            seps: Characters treated as path separators.

        Raises:
            AssertionError: If *seps* is empty or contains characters other
                than ``/``.
        """
        assert seps, "Separators must not be empty"
        assert set(seps) <= set(_seps), "Invalid separators"
        self.seps = seps

    def translate(self, pattern: str) -> str:
        """Translate *pattern* into a regular expression string."""
        return self.extend(self.match_dirs(self.translate_core(pattern)))

    def extend(self, pattern: str) -> str:
        r"""Extend *pattern* for pattern-wide concerns.

        Wraps the pattern in a non-capturing, ``DOTALL`` group so that ``.``
        matches newlines, and anchors it for a full match.
        """
        # ``\z`` is only available on Python 3.14; ``\Z`` is portable.
        return rf"(?s:{pattern})\Z"

    def match_dirs(self, pattern: str) -> str:
        """Allow *pattern* to also match archive directory entries.

        Directory entries in a ZIP archive always end in a trailing slash.
        """
        return rf"{pattern}[/]?"

    def translate_core(self, pattern: str) -> str:
        r"""Translate the core of *pattern*, without directory or anchoring handling.

        Raises:
            ValueError: If ``**`` appears anywhere other than as a full path
                segment.
        """
        self.restrict_rglob(pattern)
        return "".join(map(self.replace, separate(self.star_not_empty(pattern))))

    def replace(self, match: Match[str]) -> str:
        """Translate one token produced by :func:`separate` into regex source."""
        set_group = match.group("set")
        if set_group:
            # Retain explicit errors for reversed ranges rather than silently
            # turning a misspelled protection rule into an empty match.
            for span in re.finditer(r"(.)-(.)", set_group[1:-1]):
                if ord(span[1]) > ord(span[2]):
                    raise ValueError("invalid character range")
            return "(?!/)" + fnmatch.translate(set_group)[4:-3]
        return (
            re.escape(match.group(0))
            .replace("\\*\\*", r".*")
            .replace("\\*", rf"[^{re.escape(self.seps)}]*")
            .replace("\\?", r"[^/]")
        )

    def restrict_rglob(self, pattern: str) -> None:
        """Raise ``ValueError`` if ``**`` appears in anything but a full segment."""
        seps_pattern = rf"[{re.escape(self.seps)}]+"
        segments = re.split(seps_pattern, pattern)
        if any("**" in segment and segment != "**" for segment in segments):
            raise ValueError("** must appear alone in a path segment")

    def star_not_empty(self, pattern: str) -> str:
        """Rewrite lone ``*`` segments so they cannot match an empty segment."""

        def handle_segment(match: Match[str]) -> str:
            segment = match.group(0)
            return "?*" if segment == "*" else segment

        not_seps_pattern = rf"[^{re.escape(self.seps)}]+"
        return re.sub(not_seps_pattern, handle_segment, pattern)


def separate(pattern: str) -> Iterator[Match[str]]:
    """Split *pattern* into literal runs and bracketed character sets."""
    return re.finditer(r"([^\[]+)|(?P<set>\[!?\]?[^\]]*\])|(\[)", pattern)
