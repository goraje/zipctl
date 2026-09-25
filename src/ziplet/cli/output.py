"""Rendering helpers: safe terminal text, JSON, tables, sizes."""

from __future__ import annotations

import dataclasses
import difflib
import json
from collections.abc import Mapping, Sequence
from enum import Enum
from pathlib import PurePath
from typing import Any, TextIO

__all__ = [
    "count",
    "format_table",
    "human_size",
    "printable",
    "to_jsonable",
    "write_json",
]


def _escape(char: str) -> str:
    code = ord(char)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def printable(text: str) -> str:
    """Escape characters that must not reach a terminal as-is.

    Archive member names are attacker controlled: a name holding an ANSI escape
    sequence, a newline or a bidirectional override could rewrite what the
    terminal shows.  Non-printable characters become ``\\xNN`` / ``\\uNNNN``.
    """
    if text.isprintable():  # C speed for the usual case
        return text
    return "".join(char if char.isprintable() else _escape(char) for char in text)


def count(number: int, singular: str, plural: str | None = None) -> str:
    """Format *number* with its noun: ``1 member``, ``3 members``."""
    word = singular if number == 1 else (plural or f"{singular}s")
    return f"{number} {word}"


def human_size(size: int) -> str:
    """Format a byte count, e.g. ``1536`` -> ``'1.5 KiB'``."""
    if size < 1024:
        return f"{size} B"
    value = float(size)
    for unit in ("KiB", "MiB", "GiB"):
        value /= 1024
        if round(value, 1) < 1024:  # 1023.96 KiB is "1.0 MiB"
            return f"{value:.1f} {unit}"
    return f"{value / 1024:.1f} TiB"


def to_jsonable(value: Any) -> Any:
    """Convert dataclasses, enums, paths and collections to plain JSON data."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: to_jsonable(getattr(value, item.name))
            for item in dataclasses.fields(value)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, PurePath):
        return str(value)
    if isinstance(value, (set, frozenset)):
        return sorted(to_jsonable(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    return value


def write_json(stream: TextIO, value: Any) -> None:
    """Write *value* as one ASCII-only JSON document.

    ASCII escapes keep the output valid whatever encoding the stream has.
    """
    print(json.dumps(to_jsonable(value), indent=2, ensure_ascii=True), file=stream)


def format_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    right_aligned: Sequence[int] = (),
) -> list[str]:
    """Lay out *rows* under *headers* in space-padded columns.

    A left-aligned last column is never padded, so long names do not add
    trailing space.  The headers are upper-cased.
    """
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def render(cells: Sequence[str]) -> str:
        parts = []
        last = len(cells) - 1
        for index, cell in enumerate(cells):
            if index in right_aligned:
                parts.append(cell.rjust(widths[index]))
            elif index == last:
                parts.append(cell)
            else:
                parts.append(cell.ljust(widths[index]))
        return "  ".join(parts)

    return [
        render([header.upper() for header in headers]),
        *(render(row) for row in rows),
    ]


def did_you_mean(word: str, known: Sequence[str]) -> str:
    """`` (did you mean 'X'?)`` for the closest of *known*, or nothing."""
    close = difflib.get_close_matches(word, known, n=1)
    return f" (did you mean {close[0]!r}?)" if close else ""
