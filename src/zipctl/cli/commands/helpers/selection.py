"""Choosing archive members with shell-style patterns."""

from __future__ import annotations

import argparse
import re
from bisect import bisect_left
from collections.abc import Callable, Sequence

from zipctl.cli.errors import UsageError
from zipctl.cli.output import did_you_mean, printable
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.path.glob import Translator

__all__ = [
    "MEMBER_HELP",
    "add_match_option",
    "glob_matcher",
    "name_matcher",
    "select",
    "select_infos",
]

MEMBER_HELP = (
    "Member names or glob patterns; a directory name picks everything under it. "
    "Default: every member"
)

_TRANSLATOR = Translator()
_GLOB_CHARS = frozenset("*?[")


def glob_matcher(pattern: str) -> Callable[[str], bool]:
    """Return a predicate for member names matching *pattern*.

    ``*`` and ``?`` stay within one path segment, ``**`` crosses ``/``, and
    ``[...]`` is a character class.  A name equal to *pattern* always matches,
    so an archive member whose name contains glob characters can still be
    named literally.  Raises :class:`CliError` for a malformed pattern.
    """
    try:
        compiled = re.compile(_TRANSLATOR.translate(pattern))
    except (ValueError, re.error) as exc:
        raise UsageError(
            f"invalid pattern {printable(pattern)!r}: {printable(str(exc))}",
        ) from None
    return lambda name: name == pattern or compiled.match(name) is not None


def name_matcher(pattern: str) -> Callable[[str], bool]:
    """Return a predicate for the names *pattern* picks, as :func:`select` does.

    A plain name (no glob characters) also picks everything under it.
    """
    if not _GLOB_CHARS.isdisjoint(pattern):
        return glob_matcher(pattern)
    under = f"{pattern.rstrip('/')}/"
    return lambda name: (
        name in (pattern, under) or (under != "/" and name.startswith(under))
    )


def _under(ordered: list[str], directory: str) -> list[str]:
    """The names in sorted *ordered* that start with *directory* (ending in ``/``)."""
    start = end = bisect_left(ordered, directory)
    while end < len(ordered) and ordered[end].startswith(directory):
        end += 1
    return ordered[start:end]


def select(names: Sequence[str], patterns: Sequence[str], what: str) -> set[str]:
    """The *names* picked by *patterns* (all of them without any).

    A plain name (no glob characters) that names a directory also picks
    everything under it, as ``7z x`` and ``tar x`` do; ``unzip`` needs ``dir/*``.
    A pattern that matches nothing is a usage error, raised before any work
    is done: a typo must not leave members untouched while the command
    reports success.
    """
    if not patterns:
        return set(names)
    present = set(names)
    ordered = sorted(present)
    chosen: set[str] = set()
    dead: list[str] = []
    for pattern in patterns:
        if _GLOB_CHARS.isdisjoint(pattern):
            # A plain name matches itself, its directory entry and what is under
            # it: a lookup instead of scanning every name.  A malformed pattern
            # needs a glob character, so nothing is left unchecked.
            hit = present & {pattern, pattern + "/"}
            if directory := pattern.rstrip("/"):
                hit.update(_under(ordered, directory + "/"))
        else:
            matches = glob_matcher(pattern)
            hit = {name for name in names if matches(name)}
        if not hit:
            dead.append(pattern)
        chosen |= hit
    if dead:
        listed = ", ".join(
            f"'{printable(pattern)}'"
            + ("" if _GLOB_CHARS & set(pattern) else did_you_mean(pattern, ordered))
            for pattern in dead
        )
        raise UsageError(f"no {what} matches {listed}")
    return chosen


def select_infos(
    infos: Sequence[ZipInfo], patterns: Sequence[str], what: str = "member"
) -> list[ZipInfo]:
    """The *infos* whose names *patterns* pick, in archive order."""
    if not patterns:
        return list(infos)
    chosen = select([info.filename for info in infos], patterns, what)
    return [info for info in infos if info.filename in chosen]


def add_match_option(parser: argparse.ArgumentParser, help_text: str) -> None:
    """Add the repeatable ``--match GLOB`` option, collected into ``args.match``."""
    parser.add_argument(
        "--match", action="append", default=[], metavar="GLOB", help=help_text
    )
