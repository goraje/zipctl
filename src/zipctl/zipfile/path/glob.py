# SPDX-License-Identifier: MIT AND PSF-2.0
# Derived from CPython's zipfile (see NOTICE and licenses/CPYTHON-3.14.3.txt).
"""Glob-pattern-to-regex translation used by :class:`zipctl.zipfile.path.Path`.

Adapted from CPython's ``zipfile._path.glob`` module.  Only ``/`` is treated
as a path separator so that translated patterns behave consistently across
platforms when matched against POSIX-style archive member names.
"""

from __future__ import annotations

import fnmatch
import re
import warnings
from collections.abc import Iterator
from re import Match

__all__ = ["Translator"]

# fnmatch.translate wraps its result as ``(?s:...)\Z`` (``\z`` from 3.14).
_FNMATCH_WRAPPER = re.compile(r"\(\?s:(?P<core>.*)\)\\[Zz]", re.DOTALL)


class Translator:
    """Translate shell-style glob patterns into regular expressions.

    Only ``/`` is recognized as a path separator, matching the POSIX-style
    names stored in ZIP archives.
    """

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
            # turning a misspelled protection rule into an empty match.  The
            # set is parsed by ``re`` itself, as fnmatch's translation is, so
            # ranges pair up the same way ("[a-c-e]" is a-c, "-" and "e").
            body = set_group[1:-1].removeprefix("!")
            try:
                escaped = body.replace("\\", "\\\\").replace("[", "\\[")
                if escaped.startswith("^"):  # a literal "^", as fnmatch reads it
                    escaped = "\\" + escaped
                with warnings.catch_warnings():  # "&&", "--" etc. are literal here
                    warnings.simplefilter("ignore", FutureWarning)
                    re.compile("[" + escaped + "]")
            except re.error:
                raise ValueError("invalid character range") from None
            wrapped = _FNMATCH_WRAPPER.fullmatch(fnmatch.translate(set_group))
            if wrapped is None:  # pragma: no cover - guards a future fnmatch change
                raise ValueError(f"cannot translate {set_group!r}")
            return "(?!/)" + wrapped["core"]
        return (
            re.escape(match.group(0))
            .replace("\\*\\*", r".*")
            .replace("\\*", r"[^/]*")
            .replace("\\?", r"[^/]")
        )

    def restrict_rglob(self, pattern: str) -> None:
        """Raise ``ValueError`` if ``**`` appears in anything but a full segment."""
        seps_pattern = r"/+"
        segments = re.split(seps_pattern, pattern)
        if any("**" in segment and segment != "**" for segment in segments):
            raise ValueError("** must appear alone in a path segment")

    def star_not_empty(self, pattern: str) -> str:
        """Rewrite lone ``*`` segments so they cannot match an empty segment."""

        def handle_segment(match: Match[str]) -> str:
            segment = match.group(0)
            return "?*" if segment == "*" else segment

        not_seps_pattern = r"[^/]+"
        return re.sub(not_seps_pattern, handle_segment, pattern)


def separate(pattern: str) -> Iterator[Match[str]]:
    """Split *pattern* into literal runs and bracketed character sets.

    A "!" and a first "]" always belong to the set, as in fnmatch: the
    lookahead never gives them back, so "[]" and "[!]" with no later "]" are
    literal text, not empty sets.
    """
    return re.finditer(
        r"([^\[]+)|(?P<set>\[(?=(?P<head>!?\]?))(?P=head)[^\]]*\])|(\[)", pattern
    )
