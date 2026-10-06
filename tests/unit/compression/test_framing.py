"""Where a compressed member ends, seen through ZipFile.

Each member is written stored with a crafted payload, then given the method,
CRC and size of the data that payload decompresses to.
"""

from __future__ import annotations

import io
import struct
import zlib

import pytest

from zipctl import ZipFile
from zipctl.compression import Registry
from zipctl.compression.methods import (
    ZIP_BZIP2,
    ZIP_DEFLATED,
    ZIP_LZMA,
    ZIP_STORED,
    ZIP_ZSTANDARD,
)
from zipctl.exceptions import BadZipFile
from zipctl.zipfile.shared import CENTRAL_DIR_SIGNATURE

DATA = bytes(range(256)) * 64
METHODS = [ZIP_DEFLATED, ZIP_BZIP2, ZIP_LZMA, ZIP_ZSTANDARD]


def _compressed(method: int, data: bytes = DATA) -> bytes:
    registry = Registry()
    try:
        compressor = registry.get_compressor(method)
    except RuntimeError:
        pytest.skip(f"method {method} not available")
    return compressor.compress(data) + compressor.flush()


def _member(method: int, payload: bytes, data: bytes = DATA, flags: int = 0) -> bytes:
    """An archive of one member *payload* that says it is *data* by *method*."""
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_STORED) as zf:
        zf.writestr("m", payload)
    archive = bytearray(buffer.getvalue())
    central = archive.index(CENTRAL_DIR_SIGNATURE)
    for base, fields in ((0, (6, 8, 14, 22)), (central, (8, 10, 16, 24))):
        flag_at, method_at, crc_at, size_at = (base + f for f in fields)
        struct.pack_into("<H", archive, flag_at, flags)
        struct.pack_into("<H", archive, method_at, method)
        struct.pack_into("<L", archive, crc_at, zlib.crc32(data))
        struct.pack_into("<L", archive, size_at, len(data))
    return bytes(archive)


def _read(archive: bytes, chunk: int = -1) -> bytes:
    with ZipFile(io.BytesIO(archive)) as zf, zf.open("m") as member:
        if chunk < 0:
            return member.read()
        output = b""
        while part := member.read(chunk):
            output += part
        return output


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("chunk", [-1, 1, 1000])
def test_a_whole_stream_reads_back(method: int, chunk: int) -> None:
    assert _read(_member(method, _compressed(method)), chunk) == DATA


@pytest.mark.parametrize("method", METHODS)
def test_a_cut_stream_is_refused(method: int) -> None:
    # Flag bit 1 says an LZMA stream has its end marker, as this writer's do.
    payload = _compressed(method)[:-4]
    with pytest.raises(BadZipFile, match="Truncated compressed stream|Invalid"):
        _read(_member(method, payload, flags=0b10))


@pytest.mark.parametrize("method", [ZIP_DEFLATED, ZIP_BZIP2, ZIP_LZMA])
@pytest.mark.parametrize("junk", [b"\x00", b"junk after the stream"])
def test_bytes_after_a_single_stream_are_refused(method: int, junk: bytes) -> None:
    payload = _compressed(method) + junk
    with pytest.raises(BadZipFile, match="Data after the end of the compressed"):
        _read(_member(method, payload))


def test_bytes_after_a_zstandard_frame_are_refused() -> None:
    payload = _compressed(ZIP_ZSTANDARD) + b"junk after the stream"
    with pytest.raises(BadZipFile, match="Invalid Zstandard data"):
        _read(_member(ZIP_ZSTANDARD, payload))


def test_a_zstandard_frame_cut_after_a_whole_one_is_refused() -> None:
    first = _compressed(ZIP_ZSTANDARD, DATA[:100])
    second = _compressed(ZIP_ZSTANDARD, DATA[100:])
    with pytest.raises(BadZipFile, match="Truncated compressed stream|Invalid"):
        _read(_member(ZIP_ZSTANDARD, first + second[:-4]))


def test_two_zstandard_frames_read_as_one_member() -> None:
    payload = _compressed(ZIP_ZSTANDARD, DATA[:100])
    payload += _compressed(ZIP_ZSTANDARD, DATA[100:])
    assert _read(_member(ZIP_ZSTANDARD, payload), 1000) == DATA


def test_a_byte_after_a_stream_that_fills_the_first_read_is_refused() -> None:
    # The stream ends exactly where the reader's first read of 4096 bytes
    # does; the byte after it is only found by asking for more.
    level0 = zlib.compressobj(0, zlib.DEFLATED, -15)
    data = b"x" * (4096 - 5)  # one stored block: a 5-byte header, then data
    stream = level0.compress(data) + level0.flush()
    assert len(stream) == 4096
    with pytest.raises(
        BadZipFile, match="^Data after the end of the compressed stream$"
    ):
        _read(_member(ZIP_DEFLATED, stream + b"\x00", data), 1)


def test_lzma_without_the_end_marker_flag_ends_at_its_size() -> None:
    # Flag bit 1 clear: the stream may stop where both sizes do, so a stream
    # missing only its end marker reads; with the bit set it is cut short.
    payload = _compressed(ZIP_LZMA)
    assert _read(_member(ZIP_LZMA, payload)) == DATA
    assert _read(_member(ZIP_LZMA, payload[:-4])) == DATA
    with pytest.raises(BadZipFile, match="^Truncated compressed stream$"):
        _read(_member(ZIP_LZMA, payload[:-4], flags=0b10))


def test_a_decompressor_without_flag_bits_reads_lzma_without_an_end_marker() -> None:
    decompressor = Registry().get_decompressor(ZIP_LZMA)
    assert decompressor.decompress(_compressed(ZIP_LZMA)[:-4]) == DATA
    decompressor.finish()


def test_an_empty_zstandard_frame_between_two_reads_through() -> None:
    payload = _compressed(ZIP_ZSTANDARD, DATA[:100])
    payload += _compressed(ZIP_ZSTANDARD, b"")
    payload += _compressed(ZIP_ZSTANDARD, DATA[100:])
    assert _read(_member(ZIP_ZSTANDARD, payload), 1000) == DATA
