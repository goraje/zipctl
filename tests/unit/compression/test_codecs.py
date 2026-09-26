"""Behaviour every compression codec must share, run once per codec."""

from __future__ import annotations

import pytest

from ziplet.compression import bz2, deflate, lzma, zstd
from ziplet.compression.methods import (
    ZIP_BZIP2,
    ZIP_DEFLATED,
    ZIP_LZMA,
    ZIP_ZSTANDARD,
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
    StreamingDecompressor,
)

SAMPLE_DATA = b"Hello, codec world! " * 100

CODECS = {
    "deflate": (deflate, ZIP_DEFLATED),
    "bzip2": (bz2, ZIP_BZIP2),
    "lzma": (lzma, ZIP_LZMA),
    "zstd": (zstd, ZIP_ZSTANDARD),
}


@pytest.fixture(params=list(CODECS))
def codec(request: pytest.FixtureRequest) -> CompressionEntry:
    module, _ = CODECS[request.param]
    if module.compression_entry is None:
        pytest.skip(f"{request.param} not available")
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
    # Codecs that do not buffer input (zlib) expect the unconsumed tail back.
    for _ in range(len(data)):
        if d.eof:
            break
        tail = d.unconsumed_tail if isinstance(d, StreamingDecompressor) else b""
        part = d.decompress(tail, 17)
        assert len(part) <= 17
        output += part
    assert d.eof
    assert output == data
