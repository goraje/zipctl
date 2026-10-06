from __future__ import annotations

import struct

import pytest

from zipctl.compression import lzma
from zipctl.compression.methods import (
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
)
from zipctl.exceptions import BadZipFile
from zipctl.limits import ArchiveLimits

pytestmark = pytest.mark.skipif(
    lzma.compression_entry is None,
    reason="lzma not available",
)

SAMPLE_DATA = b"Hello, LZMA world! " * 100


def _entry() -> CompressionEntry:
    assert lzma.compression_entry is not None
    return lzma.compression_entry


class TestLzmaCompressionEntry:
    def test_compressor_factory_ignores_level(self) -> None:
        c1 = _entry().compressor_factory(None)
        c2 = _entry().compressor_factory(9)
        assert c1 is not None
        assert c2 is not None
        assert c1.compress(SAMPLE_DATA) + c1.flush() == (
            c2.compress(SAMPLE_DATA) + c2.flush()
        )


class TestLzmaCompressor:
    def _make_compressor(self) -> CompressorBase:
        compressor = _entry().compressor_factory(None)
        assert compressor is not None
        return compressor

    def test_first_compress_call_prepends_header(self) -> None:
        c = self._make_compressor()
        output = c.compress(b"x")
        # Header: 1 byte version (9), 1 byte flags (4), 2-byte props length LE
        assert len(output) >= 4
        version, flags = output[0], output[1]
        assert version == 9
        assert flags == 4
        (psize,) = struct.unpack("<H", output[2:4])
        assert psize > 0
        assert len(output) >= 4 + psize

    def test_flush_on_fresh_compressor_prepends_header(self) -> None:
        c = self._make_compressor()
        output = c.flush()
        assert len(output) >= 4
        version, flags = output[0], output[1]
        assert version == 9
        assert flags == 4


class TestLzmaDecompressor:
    def _make_decompressor(self) -> DecompressorBase:
        decompressor = _entry().decompressor_factory(0b10, ArchiveLimits())
        assert decompressor is not None
        return decompressor

    def _make_compressed(self, data: bytes = SAMPLE_DATA) -> bytes:
        c = _entry().compressor_factory(None)
        assert c is not None
        return c.compress(data) + c.flush()

    def test_partial_header_returns_empty(self) -> None:
        d = self._make_decompressor()
        # Provide only 2 bytes â€“ not enough for the header length field
        result = d.decompress(b"\x09\x04")
        assert result == b""
        with pytest.raises(BadZipFile, match="Truncated compressed stream"):
            d.finish()

    def test_header_buffer_accumulates_across_calls(self) -> None:
        compressed = self._make_compressed(b"abc")
        d = self._make_decompressor()
        # Feed byte by byte until we have a non-empty result
        output = b""
        for byte in compressed:
            output += d.decompress(bytes([byte]))
        assert output == b"abc"
