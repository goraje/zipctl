from __future__ import annotations

import io
import threading
from typing import IO

import pytest

from zipctl.zipfile.io_wrappers import ClosableZipStream, Tellable

# ---------------------------------------------------------------------------
# Tellable
# ---------------------------------------------------------------------------


class TestTellable:
    def _make(self) -> tuple[Tellable, io.BytesIO]:
        buf = io.BytesIO()
        return Tellable(buf), buf

    def test_initial_offset_is_zero(self) -> None:
        t, _ = self._make()
        assert t.tell() == 0

    def test_write_advances_offset(self) -> None:
        t, _ = self._make()
        t.write(b"hello")
        assert t.tell() == 5

    def test_write_accumulates(self) -> None:
        t, _ = self._make()
        t.write(b"abc")
        t.write(b"de")
        assert t.tell() == 5

    def test_write_delegates_to_underlying_stream(self) -> None:
        t, buf = self._make()
        t.write(b"data")
        assert buf.getvalue() == b"data"

    def test_seek_raises_unsupported_operation(self) -> None:
        t, _ = self._make()
        with pytest.raises(io.UnsupportedOperation):
            t.seek(0)

    def test_flush_does_not_raise(self) -> None:
        t, _ = self._make()
        t.write(b"x")
        t.flush()  # should not raise

    def test_close_closes_underlying_stream(self) -> None:
        t, buf = self._make()
        t.close()
        assert buf.closed


# ---------------------------------------------------------------------------
# ClosableZipStream
# ---------------------------------------------------------------------------


def _make_stream(
    data: bytes = b"",
    pos: int = 0,
    writing: bool = False,
) -> tuple[ClosableZipStream, list[IO[bytes]]]:
    buf = io.BytesIO(data)
    buf.seek(pos)
    close_calls: list[IO[bytes]] = []
    lock = threading.RLock()
    stream = ClosableZipStream(
        file=buf,
        pos=pos,
        close=lambda f: close_calls.append(f),
        lock=lock,
        writing=lambda: writing,
    )
    return stream, close_calls


class TestClosableZipStream:
    def test_tell_returns_initial_pos(self) -> None:
        stream, _ = _make_stream(pos=5)
        assert stream.tell() == 5

    def test_read_returns_data(self) -> None:
        stream, _ = _make_stream(b"hello world")
        data = stream.read(5)
        assert data == b"hello"

    def test_read_advances_position(self) -> None:
        stream, _ = _make_stream(b"hello world")
        stream.read(5)
        assert stream.tell() == 5

    def test_seek_to_absolute_position(self) -> None:
        stream, _ = _make_stream(b"hello world")
        stream.seek(6)
        assert stream.tell() == 6
        assert stream.read(5) == b"world"

    def test_seek_relative_to_current(self) -> None:
        stream, _ = _make_stream(b"hello world")
        stream.seek(3)
        stream.seek(2, io.SEEK_CUR)
        assert stream.tell() == 5

    def test_close_invokes_callback(self) -> None:
        stream, calls = _make_stream(b"data")
        stream.close()
        assert len(calls) == 1

    def test_close_is_idempotent(self) -> None:
        stream, calls = _make_stream(b"data")
        stream.close()
        stream.close()
        assert len(calls) == 1

    def test_read_raises_when_writing(self) -> None:
        buf = io.BytesIO(b"data")
        lock = threading.RLock()
        stream = ClosableZipStream(
            file=buf,
            pos=0,
            close=lambda f: None,
            lock=lock,
            writing=lambda: True,
        )
        with pytest.raises(ValueError, match="writing handle"):
            stream.read(4)

    def test_seek_raises_when_writing(self) -> None:
        buf = io.BytesIO(b"data")
        lock = threading.RLock()
        stream = ClosableZipStream(
            file=buf,
            pos=0,
            close=lambda f: None,
            lock=lock,
            writing=lambda: True,
        )
        with pytest.raises(ValueError, match="writing handle"):
            stream.seek(0)

    def test_read_raises_after_close(self) -> None:
        stream, _ = _make_stream(b"data")
        stream.close()
        with pytest.raises(ValueError, match="closed"):
            stream.read(4)
