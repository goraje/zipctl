"""A failed pipe write need not be followed by a failed flush."""

import errno
import io
from typing import TextIO, cast

import pytest
from typing_extensions import override

from zipctl.cli.streams import PipeOutput


class FailedWrite(io.StringIO):
    @override
    def write(self, text: str) -> int:
        raise OSError(errno.EINVAL, "Invalid argument")


class FailedFlush(io.StringIO):
    @override
    def flush(self) -> None:
        raise OSError(errno.EINVAL, "Invalid argument")


def test_pipe_write_is_normalized_even_when_flush_succeeds() -> None:
    underlying = FailedWrite()
    stream = PipeOutput(cast(TextIO, underlying))
    with pytest.raises(BrokenPipeError):
        stream.write("output")
    stream.flush()


def test_pipe_flush_is_normalized() -> None:
    stream = PipeOutput(cast(TextIO, FailedFlush()))
    assert stream.write("output") == 6
    with pytest.raises(BrokenPipeError):
        stream.flush()
