"""Rendering helpers: safe terminal text, JSON, tables, sizes."""

from __future__ import annotations

import dataclasses
import difflib
import json
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from enum import Enum
from pathlib import PurePath
from typing import TextIO, cast

__all__ = [
    "JsonValue",
    "count",
    "format_table",
    "human_size",
    "printable",
    "to_jsonable",
    "write_json",
]


# Sequence and Mapping are covariant, so a ``list[str]`` is JSON data too.
JsonValue = (
    str | int | float | bool | None | Sequence["JsonValue"] | Mapping[str, "JsonValue"]
)


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


def to_jsonable(value: object) -> JsonValue:
    """Convert dataclasses, enums, paths and collections to plain JSON data."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: to_jsonable(getattr(value, item.name))  # pyright: ignore[reportAny]
            for item in dataclasses.fields(value)
        }
    if isinstance(value, Enum):
        return cast("JsonValue", value.value)  # Enum.value is Any in typeshed
    if isinstance(value, PurePath):
        return str(value)
    if isinstance(value, (set, frozenset)):
        # only sets of names are written, and str has an order
        return sorted(cast("AbstractSet[str]", value))
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in cast("Sequence[object]", value)]
    if isinstance(value, Mapping):
        items = cast("Mapping[object, object]", value).items()
        return {str(key): to_jsonable(item) for key, item in items}
    if value is None or isinstance(value, (str, int, float)):
        return value
    raise TypeError(f"{type(value).__name__} is not JSON data")


def write_json(stream: TextIO, value: object) -> None:
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
        parts: list[str] = []
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
