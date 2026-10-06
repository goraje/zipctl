"""Behaviour every compression codec must share, run once per codec."""

from __future__ import annotations

import io
import random
from typing import Protocol, cast

import pytest
from typing_extensions import override

from zipctl.compression import Registry, bz2, deflate, lzma, zstd
from zipctl.compression import zstd as zstd_module
from zipctl.compression.methods import (
    ZIP_BZIP2,
    ZIP_DEFLATED,
    ZIP_LZMA,
    ZIP_ZSTANDARD,
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
    NoopCompressor,
    NoopDecompressor,
)
from zipctl.exceptions import BadZipFile
from zipctl.limits import ArchiveLimits
from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.file.ext import ZipExtFile

SAMPLE_DATA = b"Hello, codec world! " * 100


class _CodecModule(Protocol):
    compression_entry: CompressionEntry | None


CODECS: dict[str, tuple[_CodecModule, int]] = {
    "deflate": (deflate, ZIP_DEFLATED),
    "bzip2": (bz2, ZIP_BZIP2),
    "lzma": (lzma, ZIP_LZMA),
    "zstd": (zstd, ZIP_ZSTANDARD),
}


@pytest.fixture(params=list(CODECS))
def codec(request: pytest.FixtureRequest) -> CompressionEntry:
    name = cast("str", request.param)
    module, _ = CODECS[name]
    if module.compression_entry is None:
        pytest.skip(f"{name} not available")
    assert isinstance(module.compression_entry, CompressionEntry)
    return module.compression_entry


def _compress(codec: CompressionEntry, data: bytes, level: int | None = None) -> bytes:
    c = codec.compressor_factory(level)
    assert isinstance(c, CompressorBase)
    return c.compress(data) + c.flush()


def _decompressor(codec: CompressionEntry) -> DecompressorBase:
    d = codec.decompressor_factory(0b10, ArchiveLimits())
    assert isinstance(d, DecompressorBase)
    return d


@pytest.mark.parametrize("name", list(CODECS))
def test_entry_maps_to_its_zip_method(name: str) -> None:
    module, method = CODECS[name]
    if module.compression_entry is None:
        pytest.skip(f"{name} not available")
    assert module.compression_entry.compression_method == method


@pytest.mark.parametrize("level", [None, 1, 9])
def test_round_trip_at_every_level(codec: CompressionEntry, level: int | None) -> None:
    compressed = _compress(codec, SAMPLE_DATA, level)
    assert _decompressor(codec).decompress(compressed) == SAMPLE_DATA


def test_repetitive_data_gets_smaller(codec: CompressionEntry) -> None:
    assert len(_compress(codec, SAMPLE_DATA)) < len(SAMPLE_DATA)


def test_empty_input_round_trips(codec: CompressionEntry) -> None:
    compressed = _compress(codec, b"")
    assert _decompressor(codec).decompress(compressed) == b""


def test_chunked_compress_round_trip(codec: CompressionEntry) -> None:
    c = codec.compressor_factory(None)
    assert c is not None
    compressed = b""
    for i in range(0, len(SAMPLE_DATA), 50):
        compressed += c.compress(SAMPLE_DATA[i : i + 50])
    compressed += c.flush()
    assert _decompressor(codec).decompress(compressed) == SAMPLE_DATA


def test_chunked_decompress_round_trip(codec: CompressionEntry) -> None:
    compressed = _compress(codec, SAMPLE_DATA)
    d = _decompressor(codec)
    output = b""
    for i in range(0, len(compressed), 20):
        output += d.decompress(compressed[i : i + 20])
    assert output == SAMPLE_DATA
    d.finish()


def test_finish_only_after_full_stream(codec: CompressionEntry) -> None:
    compressed = _compress(codec, SAMPLE_DATA)
    d = _decompressor(codec)
    with pytest.raises(BadZipFile, match="Truncated compressed stream"):
        d.finish()
    d.decompress(compressed)
    d.finish()


def test_decompress_respects_max_length(codec: CompressionEntry) -> None:
    data = SAMPLE_DATA * 100
    compressed = _compress(codec, data)
    d = _decompressor(codec)
    output = d.decompress(compressed, 17)
    assert len(output) <= 17
    # All input is in; each call drains what the decompressor still holds.
    while part := d.decompress(b"", 17):
        assert len(part) <= 17
        output += part
    d.finish()
    assert output == data


def test_needs_input_once_the_stream_has_ended(codec: CompressionEntry) -> None:
    d = _decompressor(codec)
    d.decompress(_compress(codec, SAMPLE_DATA))
    # Input after the end must reach decompress(), which refuses it.
    assert d.needs_input


requires_zstd = pytest.mark.skipif(
    zstd_module.zstd is None, reason="needs compression.zstd or backports.zstd"
)


def _zstd_frame(data: bytes) -> bytes:
    module = zstd_module.zstd
    assert module is not None
    compressor = module.ZstdCompressor()
    return compressor.compress(data) + compressor.flush()


class _TwoFrames(CompressorBase):
    """Writes its input as two Zstandard frames, the first *first_size* bytes long."""

    def __init__(self, first_size: int) -> None:
        self._first_size: int = first_size
        self._data: bytes = b""

    @override
    def compress(self, data: bytes) -> bytes:
        self._data += data
        return b""

    @override
    def flush(self) -> bytes:
        cut = self._first_size
        return _zstd_frame(self._data[:cut]) + _zstd_frame(self._data[cut:])


@requires_zstd
@pytest.mark.parametrize(
    "frame_end", [ZipExtFile.MIN_READ_SIZE, ZipExtFile.MAX_READ_SIZE, 1000]
)
@pytest.mark.parametrize("chunk", [ZipExtFile.MIN_READ_SIZE, -1])
def test_zstd_entry_of_several_frames_reads_completely(
    frame_end: int, chunk: int
) -> None:
    data = random.Random(frame_end).randbytes(frame_end + 5000)
    # Incompressible data: a frame is its content plus a small overhead, so
    # this converges on a first frame ending exactly at *frame_end*.
    first_size = frame_end
    for _ in range(5):
        first_size += frame_end - len(_zstd_frame(data[:first_size]))
    assert len(_zstd_frame(data[:first_size])) == frame_end
    registry = Registry()
    entry = zstd_module.compression_entry
    assert entry is not None
    registry.register(
        ZIP_ZSTANDARD,
        CompressionEntry(
            ZIP_ZSTANDARD,
            lambda _level: _TwoFrames(first_size),
            entry.decompressor_factory,
        ),
    )
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression_registry=registry) as archive:
        archive.writestr("m", data, compress_type=ZIP_ZSTANDARD)
    with ZipFile(buffer) as archive, archive.open("m") as member:
        output = b""
        while part := member.read(chunk):
            output += part
    assert output == data


def test_custom_method_on_noop_codecs_reads_in_small_chunks() -> None:
    registry = Registry()
    registry.register(
        250,
        CompressionEntry(
            250,
            lambda _level: NoopCompressor(),
            lambda _flags, _limits: NoopDecompressor(),
        ),
    )
    data = random.Random(250).randbytes(10240)
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression_registry=registry) as archive:
        archive.writestr("m", data, compress_type=250)
    with (
        ZipFile(buffer, compression_registry=registry) as archive,
        archive.open("m") as member,
    ):
        output = b""
        while part := member.read(100):
            output += part
        member.seek(0)
        assert member.read(1000) == data[:1000]
    assert output == data


class _Stalled(DecompressorBase):
    """Takes its first input, then claims to hold more but never returns any."""

    def __init__(self) -> None:
        self.calls: int = 0

    @property
    @override
    def needs_input(self) -> bool:
        return self.calls == 0

    @override
    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        self.calls += 1
        assert self.calls < 100, "the reader keeps calling a stalled decompressor"
        return b""

    @override
    def finish(self) -> None:
        pass


def test_a_decompressor_that_makes_no_progress_is_refused() -> None:
    registry = Registry()
    registry.register(
        251,
        CompressionEntry(
            251,
            lambda _level: NoopCompressor(),
            lambda _flags, _limits: _Stalled(),
        ),
    )
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression_registry=registry) as archive:
        archive.writestr("m", random.Random(251).randbytes(10240), compress_type=251)
    with (
        ZipFile(buffer, compression_registry=registry) as archive,
        archive.open("m") as member,
        pytest.raises(BadZipFile, match="made no progress"),
    ):
        member.read(100)  # leaves input unread after the first raw read


class _WithTrailingBytes(CompressorBase):
    """Writes *codec*'s stream for its input, then bytes after the stream's end."""

    def __init__(self, codec: CompressionEntry) -> None:
        self._codec: CompressionEntry = codec
        self._data: bytes = b""

    @override
    def compress(self, data: bytes) -> bytes:
        self._data += data
        return b""

    @override
    def flush(self) -> bytes:
        return _compress(self._codec, self._data) + b"trailing"


def test_bytes_after_an_lzma_stream_ending_on_a_read_boundary_are_refused() -> None:
    entry = lzma.compression_entry
    if entry is None:
        pytest.skip("lzma not available")
    boundary = ZipExtFile.MIN_READ_SIZE
    data = random.Random(1).randbytes(2 * boundary)
    # Incompressible data: this converges on a stream ending at *boundary*.
    size = boundary - 200
    for _ in range(5):
        size += boundary - len(_compress(entry, data[:size]))
    assert len(_compress(entry, data[:size])) == boundary
    registry = Registry()
    registry.register(
        ZIP_LZMA,
        CompressionEntry(
            ZIP_LZMA,
            lambda _level: _WithTrailingBytes(entry),
            entry.decompressor_factory,
        ),
    )
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression_registry=registry) as archive:
        archive.writestr("m", data[:size], compress_type=ZIP_LZMA)
    with (
        ZipFile(buffer) as archive,
        pytest.raises(BadZipFile, match="Data after the end"),
    ):
        archive.read("m")


@requires_zstd
def test_zstd_is_not_finished_inside_a_second_frame() -> None:
    entry = zstd_module.compression_entry
    assert entry is not None
    d = _decompressor(entry)
    output = d.decompress(_zstd_frame(b"one") + _zstd_frame(b"two")[:5])
    while not d.needs_input:
        output += d.decompress(b"")
    assert output == b"one"
    with pytest.raises(BadZipFile, match="Truncated compressed stream"):
        d.finish()


@requires_zstd
def test_zstd_level_22_reads_back_under_the_default_limits() -> None:
    buffer = io.BytesIO()
    data = b"level twenty-two " * 4096
    with ZipFile(buffer, "w", compression=ZIP_ZSTANDARD, compresslevel=22) as zf:
        zf.writestr("a", data)
    with ZipFile(buffer) as zf:
        assert zf.read("a") == data


def test_garbage_is_refused_with_a_typed_error(codec: CompressionEntry) -> None:
    d = _decompressor(codec)
    with pytest.raises(BadZipFile, match="Invalid"):
        d.decompress(random.Random(1).randbytes(64))


def test_an_lzma_header_with_the_wrong_properties_size_is_refused() -> None:
    if lzma.compression_entry is None:
        pytest.skip("lzma not available")
    d = _decompressor(lzma.compression_entry)
    with pytest.raises(BadZipFile, match="Invalid ZIP LZMA properties size"):
        d.decompress(b"\x09\x14\x04\x00" + b"\x5d\x00\x00\x10")
