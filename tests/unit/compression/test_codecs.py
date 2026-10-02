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
)
from zipctl.zipfile.ext import ZipExtFile
from zipctl.zipfile.file import ZipFile

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
    d = codec.decompressor_factory()
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
    assert d.eof is True


def test_eof_only_after_full_stream(codec: CompressionEntry) -> None:
    compressed = _compress(codec, SAMPLE_DATA)
    d = _decompressor(codec)
    assert d.eof is False
    d.decompress(compressed)
    assert d.eof is True


def test_decompress_respects_max_length(codec: CompressionEntry) -> None:
    data = SAMPLE_DATA * 100
    compressed = _compress(codec, data)
    d = _decompressor(codec)
    output = d.decompress(compressed, 17)
    assert len(output) <= 17
    # All input is in; each call drains what the decompressor still holds.
    for _ in range(len(data)):
        if d.eof:
            break
        assert not d.needs_input
        part = d.decompress(b"", 17)
        assert len(part) <= 17
        output += part
    assert d.eof
    assert output == data


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


@requires_zstd
def test_zstd_is_not_at_eof_inside_a_second_frame() -> None:
    entry = zstd_module.compression_entry
    assert entry is not None
    d = _decompressor(entry)
    assert d.concatenated
    output = d.decompress(_zstd_frame(b"one") + _zstd_frame(b"two")[:5])
    while not d.needs_input:
        output += d.decompress(b"")
    assert output == b"one"
    assert not d.eof
