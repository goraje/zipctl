"""Raw-deflate specifics; shared behaviour is in test_codecs."""

from __future__ import annotations

import sys
import zlib

import pytest

from ziplet.compression import deflate
from ziplet.compression.methods import CompressorBase, StreamingDecompressor

pytestmark = pytest.mark.skipif(
    deflate.compression_entry is None,
    reason="zlib not available",
)

SAMPLE_DATA = b"Hello, World! " * 100


def _decompressor() -> StreamingDecompressor:
    assert deflate.compression_entry is not None
    decompressor = deflate.compression_entry.decompressor_factory()
    assert isinstance(decompressor, StreamingDecompressor)
    return decompressor


def _raw_deflate(data: bytes) -> bytes:
    if sys.version_info >= (3, 11):
        return zlib.compress(data, wbits=-15)
    c = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


@pytest.mark.parametrize("level", [None, 1, 9])
def test_compressor_output_is_raw_deflate(level: int | None) -> None:
    assert deflate.compression_entry is not None
    c = deflate.compression_entry.compressor_factory(level)
    assert isinstance(c, CompressorBase)
    assert zlib.decompress(c.compress(SAMPLE_DATA) + c.flush(), -15) == SAMPLE_DATA


def test_decompressor_reads_stdlib_stream() -> None:
    assert _decompressor().decompress(_raw_deflate(SAMPLE_DATA)) == SAMPLE_DATA


def test_negative_max_length_means_unlimited() -> None:
    result = _decompressor().decompress(_raw_deflate(SAMPLE_DATA), max_length=-1)
    assert result == SAMPLE_DATA


def test_max_length_leaves_remainder_in_unconsumed_tail() -> None:
    d = _decompressor()
    assert d.unconsumed_tail == b""
    d.decompress(_raw_deflate(SAMPLE_DATA), max_length=10)
    assert d.unconsumed_tail != b""


def test_flush_after_full_stream_is_empty() -> None:
    d = _decompressor()
    d.decompress(_raw_deflate(SAMPLE_DATA))
    assert d.flush() == b""


def test_empty_input_yields_nothing() -> None:
    assert _decompressor().decompress(b"") == b""
