"""bzip2 output must match the stdlib format; shared behaviour is in test_codecs."""

from __future__ import annotations

import bz2 as _bz2

import pytest

from zipctl.compression import bz2

pytestmark = pytest.mark.skipif(
    bz2.compression_entry is None,
    reason="bz2 not available",
)

SAMPLE_DATA = b"Hello, bzip2 world! " * 100


@pytest.mark.parametrize("level", [None, 1, 9])
def test_compressor_output_is_readable_by_stdlib(level: int | None) -> None:
    assert bz2.compression_entry is not None
    c = bz2.compression_entry.compressor_factory(level)
    assert c is not None
    assert _bz2.decompress(c.compress(SAMPLE_DATA) + c.flush()) == SAMPLE_DATA


def test_decompressor_reads_stdlib_stream() -> None:
    assert bz2.compression_entry is not None
    d = bz2.compression_entry.decompressor_factory()
    assert d is not None
    assert d.decompress(_bz2.compress(SAMPLE_DATA)) == SAMPLE_DATA
    assert d.eof is True
