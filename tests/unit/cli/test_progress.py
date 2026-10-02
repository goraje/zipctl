"""``StepReporter`` and the renderer's status words."""

from __future__ import annotations

import io
import os
import struct
import sys
from collections.abc import Iterator

import pytest
from typing_extensions import override

from zipctl.cli.commands.helpers.progress import (
    ProgressRenderer,
    StepReporter,
    progress_renderer,
)
from zipctl.zipfile.policy import MemberStatus
from zipctl.zipfile.progress import ProgressEvent, ProgressPhase

HAS_PTY = sys.platform != "win32"


def test_steps_report_a_start_and_a_finish_with_running_totals() -> None:
    events: list[ProgressEvent] = []
    steps = StepReporter(events.append, [("a", 10), ("b", 30)])
    steps.start(0)
    steps.finish(0, ok=True)
    steps.start(1)
    steps.finish(1, ok=False)

    assert [e.phase for e in events] == [
        ProgressPhase.START,
        ProgressPhase.FINISH,
        ProgressPhase.START,
        ProgressPhase.FINISH,
    ]
    assert [e.total_bytes_done for e in events] == [0, 10, 10, 40]
    assert {e.total_bytes for e in events} == {40}
    assert [e.member_count for e in events] == [2, 2, 2, 2]
    assert events[1].status is MemberStatus.EXTRACTED
    assert events[3].status is MemberStatus.FAILED
    assert events[0].status is None


def test_a_plain_stream_gets_one_status_line_per_finished_member() -> None:
    stream = io.StringIO()
    renderer = ProgressRenderer(stream, live=False)
    steps = StepReporter(renderer, [("a.txt", 1), ("b.txt", 2)])
    steps.start(0)
    steps.finish(0, ok=True)
    steps.finish(1, ok=False)
    assert stream.getvalue() == "[1/2] OK      a.txt\n[2/2] FAILED  b.txt\n"


def test_a_step_reporter_without_a_callback_does_nothing_and_reads_no_members() -> None:
    def members() -> Iterator[tuple[str, int]]:
        raise AssertionError("members must not be read")
        yield ("never", 0)  # pyright: ignore[reportUnreachable]  # makes members() a generator

    steps = StepReporter(None, members())
    steps.start(0)
    steps.finish(0, ok=True)


class Clock:
    def __init__(self) -> None:
        self.now: float = 0.0

    def __call__(self) -> float:
        return self.now


def test_the_live_line_is_redrawn_at_most_every_50_ms() -> None:
    stream, clock = io.StringIO(), Clock()
    renderer = ProgressRenderer(stream, live=True, clock=clock)
    steps = StepReporter(renderer, [(f"m{i}", 1) for i in range(4)])

    def redraws() -> int:
        return stream.getvalue().count("\r")

    steps.start(0)  # the first event is always drawn
    steps.finish(0, ok=True)
    steps.start(1)
    assert redraws() == 1
    clock.now = 0.06
    steps.finish(1, ok=True)
    assert redraws() == 2
    steps.start(2)
    steps.finish(2, ok=True)
    assert redraws() == 2
    steps.start(3)
    steps.finish(3, ok=True)  # the last member finishing is always drawn
    assert redraws() == 3
    assert "4/4" in stream.getvalue().rsplit("\r", 1)[1]


def test_the_line_is_drawn_at_once_after_it_was_cleared_for_a_prompt() -> None:
    stream, clock = io.StringIO(), Clock()
    renderer = ProgressRenderer(stream, live=True, clock=clock)
    steps = StepReporter(renderer, [("a", 1), ("b", 1), ("c", 1)])
    steps.start(0)
    renderer.clear()
    before = stream.getvalue().count("[2/3]")
    steps.start(1)
    assert stream.getvalue().count("[2/3]") == before + 1


@pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")
def test_the_status_line_fits_the_terminal_it_is_drawn_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Width comes from the progress stream, not from (redirected) standard output."""
    import fcntl  # POSIX only, so imported here rather than at module level
    import pty
    import termios

    monkeypatch.delenv("COLUMNS", raising=False)
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 40, 0, 0))
    try:
        with os.fdopen(slave, "w", closefd=False) as stream:
            renderer = ProgressRenderer(stream, live=True)
            renderer(
                ProgressEvent(
                    phase=ProgressPhase.START,
                    member="a_member_name_that_is_far_longer_than_forty_columns.txt",
                    member_index=0,
                    member_count=1,
                    member_bytes=0,
                    member_total=10,
                    total_bytes=10,
                    total_bytes_done=0,
                    status=None,
                )
            )
        drawn = os.read(master, 4096).decode().lstrip("\r")
    finally:
        os.close(master)
        os.close(slave)
    assert 0 < len(drawn.strip()) < 40
    assert "..." in drawn


class _Terminal(io.StringIO):
    @override
    def isatty(self) -> bool:
        return True


def test_the_renderer_is_off_without_progress_and_closed_after_a_failure() -> None:
    with progress_renderer(io.StringIO(), False) as none:
        assert none is None
    stream = _Terminal()
    with pytest.raises(RuntimeError):  # noqa: PT012
        with progress_renderer(stream, True) as renderer:
            StepReporter(renderer, [("a", 1)]).start(0)
            assert stream.getvalue().strip()  # a status line is up
            raise RuntimeError
    assert stream.getvalue().endswith("\r")  # closing erased it
