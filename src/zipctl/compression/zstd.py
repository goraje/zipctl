from __future__ import annotations

from importlib import import_module
from typing import Protocol, cast

from typing_extensions import override

from zipctl.compression.methods import (
    ZIP_ZSTANDARD,
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
    truncated,
)
from zipctl.exceptions import BadZipFile
from zipctl.limits import ArchiveLimits, ArchiveResourceLimitError

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_MAX_FRAME_HEADER = 18  # magic, descriptor, window, dictionary ID, size


class _ZstdCompressorLike(Protocol):
    def compress(self, data: bytes) -> bytes: ...

    def flush(self) -> bytes: ...


class _ZstdDecompressorLike(Protocol):
    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    @property
    def unused_data(self) -> bytes: ...

    def decompress(self, data: bytes, max_length: int = -1) -> bytes: ...


class _ZstdModule(Protocol):
    """The part of ``compression.zstd`` used here."""

    def ZstdCompressor(
        self, *, level: int | None = None, options: dict[int, int] | None = None
    ) -> _ZstdCompressorLike: ...

    def ZstdDecompressor(
        self, *, options: dict[int, int] | None = None
    ) -> _ZstdDecompressorLike: ...

    ZstdError: type[Exception]


def _load_zstd() -> _ZstdModule | None:
    """Return the stdlib ``compression.zstd`` (3.14+), else ``backports.zstd``.

    Loaded dynamically so type checking behaves the same on every Python
    version and whether or not the optional backport is installed.
    """
    for name in ("compression.zstd", "backports.zstd"):
        try:
            # The import is dynamic, so the module is only known by its use here
            return cast("_ZstdModule", cast("object", import_module(name)))
        except ImportError:
            continue
    return None


zstd = _load_zstd()

compression_entry: CompressionEntry | None = None

if zstd is not None:
    _module: _ZstdModule = zstd

    def _frame_window(head: bytes) -> int | None:
        """The window size a Zstandard frame header declares, if *head* has one.

        Follows RFC 8878 section 3.1.1.1: a Window_Descriptor, or for a
        single-segment frame the Frame_Content_Size.
        """
        if len(head) < 5 or head[:4] != _ZSTD_MAGIC:
            return None
        descriptor = head[4]
        if not descriptor & 0x20:  # not single segment: a Window_Descriptor
            if len(head) < 6:
                return None
            exponent, mantissa = head[5] >> 3, head[5] & 7
            base = 1 << (10 + exponent)
            return base + (base >> 3) * mantissa
        dictionary = (0, 1, 2, 4)[descriptor & 3]
        size = (1, 2, 4, 8)[descriptor >> 6]
        start = 5 + dictionary
        if len(head) < start + size:
            return None
        value = int.from_bytes(head[start : start + size], "little")
        return value + 256 if size == 2 else value

    class _ZstdCompressor(CompressorBase):
        """Wraps zstd.ZstdCompressor to satisfy CompressorBase.

        Attributes:
            _c: The underlying zstd.ZstdCompressor instance.
        """

        def __init__(self, level: int | None) -> None:
            """Initializes the compressor with an optional compression level.

            Args:
                level: The Zstandard compression level. If None, the default
                    compression level is used.
            """
            if level is not None and level >= 22:
                # Level 22 defaults to a 128 MiB window, past the 64 MiB that
                # ArchiveLimits accepts when reading; no other level exceeds it.
                # Parameters 100 and 101: ZSTD_c_compressionLevel, ZSTD_c_windowLog.
                options = {100: level, 101: 26}
                self._c: _ZstdCompressorLike = _module.ZstdCompressor(options=options)
            else:
                self._c = _module.ZstdCompressor(level=level)

        @override
        def compress(self, data: bytes) -> bytes:
            """Compresses a chunk of data.

            Args:
                data: The raw bytes to compress.

            Returns:
                Compressed bytes. May be empty if data is buffered internally.
            """
            return self._c.compress(data)

        @override
        def flush(self) -> bytes:
            """Flushes any remaining buffered data and finalizes the stream.

            Returns:
                The remaining compressed bytes.
            """
            return self._c.flush()

    class _ZstdDecompressor(DecompressorBase):
        """Wraps zstd.ZstdDecompressor to satisfy DecompressorBase.

        A Zstandard stream may hold several frames back to back (multithreaded
        compressors write them); each gets a fresh decoder, starting with the
        bytes the previous one left unused.  The stream ends with its input,
        which must end with a frame.

        Attributes:
            _d: The decoder of the current frame.
        """

        def __init__(self, flag_bits: int, limits: ArchiveLimits) -> None:
            """Initializes the decompressor under the window limit of *limits*."""
            del flag_bits
            window = limits.max_zstd_window_bytes
            # ZSTD_d_windowLogMax is the stable public libzstd parameter 100.
            self._window_log: int | None = (
                None if window is None else window.bit_length() - 1
            )
            self._options: dict[int, int] | None = (
                None if self._window_log is None else {100: self._window_log}
            )
            self._head: bytes = b""  # the current frame's first bytes
            self._d: _ZstdDecompressorLike = _module.ZstdDecompressor(
                options=self._options
            )

        @property
        @override
        def needs_input(self) -> bool:
            if self._d.eof:
                return not self._d.unused_data
            return self._d.needs_input

        @override
        def decompress(self, data: bytes, max_length: int = -1) -> bytes:
            """Decompresses a chunk of data, starting a new frame if one ended.

            Args:
                data: The compressed bytes to decompress.

            Returns:
                Decompressed bytes.
            """
            result = self._decompress_frame(data, max_length)
            while not result and self._d.eof and self._d.unused_data:
                # An empty frame; go on to the next.
                result = self._decompress_frame(b"", max_length)
            return result

        def _decompress_frame(self, data: bytes, max_length: int) -> bytes:
            if self._d.eof:
                data = self._d.unused_data + data
                if not data:
                    return b""
                self._d = _module.ZstdDecompressor(options=self._options)
                self._head = b""
            if len(self._head) < _MAX_FRAME_HEADER:
                self._head += data[: _MAX_FRAME_HEADER - len(self._head)]
            try:
                return self._d.decompress(data, max_length)
            except (_module.ZstdError, EOFError) as exc:
                # Told apart by the frame header, not by libzstd's wording.
                window = _frame_window(self._head)
                if (
                    self._window_log is not None
                    and window is not None
                    and window > 1 << self._window_log
                ):
                    raise ArchiveResourceLimitError(
                        "Zstandard window exceeds configured limit"
                    ) from exc
                raise BadZipFile("Invalid Zstandard data") from exc

        @override
        def finish(self) -> None:
            if not self._d.eof:
                raise truncated()

    compression_entry = CompressionEntry(
        compression_method=ZIP_ZSTANDARD,
        compressor_factory=_ZstdCompressor,
        decompressor_factory=_ZstdDecompressor,
        levels=range(-131072, 23),  # libzstd's minimum and maximum levels
    )
