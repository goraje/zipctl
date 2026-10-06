"""Rendering :class:`~zipctl.ProgressEvent` on standard error."""

from __future__ import annotations

import argparse
import os
import time
from collections.abc import Callable, Generator, Iterable
from contextlib import contextmanager
from typing import Protocol, TextIO
from unicodedata import east_asian_width

from zipctl.cli.output import Output, human_size, printable
from zipctl.zipfile.policy import MemberStatus
from zipctl.zipfile.progress import ProgressCallback, ProgressEvent, ProgressPhase

__all__ = [
    "ProgressArgs",
    "ProgressRenderer",
    "StepReporter",
    "add_progress_option",
    "progress_renderer",
]

_FALLBACK_WIDTH = 80
_REDRAW_INTERVAL = 0.05  # seconds between redraws of the live status line
_STATUS_WORDS = {
    MemberStatus.EXTRACTED: "OK",
    MemberStatus.PREVIEWED: "OK",
    MemberStatus.SKIPPED: "SKIP",
    MemberStatus.FAILED: "FAILED",
}


def _columns(text: str) -> int:
    """Terminal columns *text* takes: East Asian wide characters take two."""
    return sum(2 if east_asian_width(char) in "WF" else 1 for char in text)


def _terminal_width(stream: TextIO) -> int:
    """Columns of the terminal *stream* is attached to (it is not standard output)."""
    try:
        return os.get_terminal_size(stream.fileno()).columns or _FALLBACK_WIDTH
    except (OSError, ValueError, AttributeError):  # not a terminal, or no fileno
        return _FALLBACK_WIDTH


def _prefix(text: str, columns: int) -> str:
    """The longest start of *text* that fits in *columns*."""
    used = 0
    for index, char in enumerate(text):
        used += _columns(char)
        if used > columns:
            return text[:index]
    return text


def _shorten(text: str, width: int) -> str:
    """Trim *text* to *width* columns, keeping both ends of long names."""
    if width < 8 or _columns(text) <= width:
        return _prefix(text, max(width, 0))
    keep = width - 3
    head = keep // 2
    tail = _prefix(text[::-1], keep - head)[::-1]
    return f"{_prefix(text, head)}...{tail}"


class ProgressRenderer:
    """A ``progress=`` callback that reports on *stream*.

    On a terminal it keeps one status line up to date (``\\r`` rewrites); when
    output is redirected it prints one plain line per finished member instead
    (``[1/3] OK      name``), so logs stay readable.  The live line is redrawn at
    most every 50 ms, except for the first event and the last member finishing,
    which are always drawn.
    """

    def __init__(
        self,
        stream: TextIO,
        *,
        live: bool,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._stream: TextIO = stream
        self._live: bool = live
        self._clock: Callable[[], float] = clock
        self._drawn: int = 0
        self._last_draw: float | None = None

    def __call__(self, event: ProgressEvent) -> None:
        if self._live:
            self._draw(event)
        elif event.phase is ProgressPhase.FINISH and event.status is not None:
            print(
                f"[{event.member_index + 1}/{event.member_count}] "
                f"{_STATUS_WORDS[event.status]:<8}{printable(event.member)}",
                file=self._stream,
            )

    def _due(self, event: ProgressEvent) -> bool:
        if self._last_draw is None:
            return True
        last = (
            event.phase is ProgressPhase.FINISH
            and event.member_index + 1 == event.member_count
        )
        return last or self._clock() - self._last_draw >= _REDRAW_INTERVAL

    def _draw(self, event: ProgressEvent) -> None:
        if not self._due(event):
            return
        self._last_draw = self._clock()
        if event.total_bytes:
            percent = min(100, event.total_bytes_done * 100 // event.total_bytes)
        else:
            percent = 100 if event.phase is ProgressPhase.FINISH else 0
        tail = (
            f"  {percent:3d}%  {human_size(event.total_bytes_done)}"
            f"/{human_size(event.total_bytes)}"
        )
        head = f"[{event.member_index + 1}/{event.member_count}] "
        width = _terminal_width(self._stream) - 1
        name = _shorten(printable(event.member), width - len(head) - len(tail))
        self._write(head + name + tail)

    def _write(self, line: str) -> None:
        columns = _columns(line)
        padding = " " * max(0, self._drawn - columns)
        self._stream.write(f"\r{line}{padding}")
        self._stream.flush()
        self._drawn = columns

    def clear(self) -> None:
        """Erase the status line, e.g. before a password prompt."""
        if self._live and self._drawn:
            self._stream.write("\r" + " " * self._drawn + "\r")
            self._stream.flush()
            self._drawn = 0
        self._last_draw = None  # what comes next is drawn at once

    def close(self) -> None:
        """Same as :meth:`clear`."""
        self.clear()


class ProgressArgs(Protocol):
    """What :func:`add_progress_option` leaves on the parsed arguments."""

    progress: bool


def add_progress_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--progress", action="store_true", help="report progress on standard error"
    )


@contextmanager
def progress_renderer(
    output: Output, enabled: bool
) -> Generator[ProgressRenderer | None]:
    """The renderer for ``--progress`` (``None`` without it), closed on the way out.

    While it runs, a password prompt clears its status line first.
    """
    if not enabled:
        yield None
        return
    stream = output.stderr
    renderer = ProgressRenderer(stream, live=stream.isatty())
    previous, output.clear_line = output.clear_line, renderer.clear
    try:
        yield renderer
    finally:
        output.clear_line = previous
        renderer.close()


class StepReporter:
    """Progress events for a command that does its own work member by member.

    Extraction reports progress from inside the library; ``test`` and ``create``
    call :meth:`start` and :meth:`finish` around each member instead.  Sizes are
    the declared ones, and there is one event pair per member (no byte-level
    progress inside a member).  Without a *callback* every call does nothing,
    and *members* is never read (so it may be a lazy iterable).
    """

    def __init__(
        self, callback: ProgressCallback | None, members: Iterable[tuple[str, int]]
    ) -> None:
        self._callback: ProgressCallback | None = callback
        self._members: list[tuple[str, int]] = list(members) if callback else []
        self._total: int = sum(size for _, size in self._members)
        self._done: int = 0

    def _event(
        self, phase: ProgressPhase, index: int, status: MemberStatus | None = None
    ) -> ProgressEvent:
        name, size = self._members[index]
        finished = phase is ProgressPhase.FINISH
        return ProgressEvent(
            phase=phase,
            member=name,
            member_index=index,
            member_count=len(self._members),
            member_bytes=size if finished else 0,
            member_total=size,
            total_bytes=self._total,
            total_bytes_done=self._done,
            status=status,
        )

    def start(self, index: int) -> None:
        if self._callback:
            self._callback(self._event(ProgressPhase.START, index))

    def finish(self, index: int, *, ok: bool) -> None:
        if self._callback:
            self._done += self._members[index][1]
            status = MemberStatus.EXTRACTED if ok else MemberStatus.FAILED
            self._callback(self._event(ProgressPhase.FINISH, index, status))
