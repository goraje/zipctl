from __future__ import annotations

from importlib import import_module
from typing import Protocol, cast

from typing_extensions import override

from zipctl.compression.methods import (
    ZIP_ZSTANDARD,
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
)
from zipctl.exceptions import BadZipFile
from zipctl.limits import ArchiveLimits, ArchiveResourceLimitError

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_ZSTD_FCS_BYTES = (0, 2, 4, 8)  # indexed by the frame-content-size flag


def _frame_window(head: bytes) -> int | None:
    """The window size a Zstandard frame declares, or ``None`` if not known yet.

    Reads RFC 8878 section 3.1.1.1 directly, so the budget is enforced from
    the frame header and not from a decoder's error message.
    """
    if len(head) < 5:
        return None
    if head[:4] != _ZSTD_MAGIC:
        return 0  # skippable or invalid; the decoder reports it
    descriptor = head[4]
    single_segment = bool(descriptor & 0x20)
    if not single_segment:
        if len(head) < 6:
            return None
        exponent, mantissa = head[5] >> 3, head[5] & 7
        base = 1 << (10 + exponent)
        return base + base // 8 * mantissa
    flag = descriptor >> 6
    width = _ZSTD_FCS_BYTES[flag] or 1
    # skip the dictionary id (0, 1, 2 or 4 bytes) to reach the content size
    start = 5 + (0, 1, 2, 4)[descriptor & 0x03]
    if len(head) < start + width:
        return None
    size = int.from_bytes(head[start : start + width], "little")
    return size + 256 if flag == 1 else size


class _ZstdCompressorLike(Protocol):
    def compress(self, data: bytes) -> bytes: ...

    def flush(self) -> bytes: ...


class _ZstdDecompressorLike(Protocol):
    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    def decompress(self, data: bytes, max_length: int = -1) -> bytes: ...


class _ZstdModule(Protocol):
    """The part of ``compression.zstd`` used here."""

    def ZstdCompressor(self, *, level: int | None = None) -> _ZstdCompressorLike: ...

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
            self._c: _ZstdCompressorLike = _module.ZstdCompressor(level=level)

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

        Attributes:
            _d: The underlying zstd.ZstdDecompressor instance.
        """

        def __init__(self) -> None:
            """Initializes the decompressor."""
            self._d: _ZstdDecompressorLike = _module.ZstdDecompressor()
            self._window_limit: int | None = None
            self._head: bytes | None = b""  # frame header bytes until checked

        @override
        def configure_limits(self, limits: ArchiveLimits) -> None:
            self._window_limit = limits.max_zstd_window_bytes
            if self._window_limit is not None:
                # ZSTD_d_windowLogMax is the stable public libzstd parameter 100.
                self._d = _module.ZstdDecompressor(
                    options={100: self._window_limit.bit_length() - 1}
                )

        @property
        @override
        def eof(self) -> bool:
            """Whether the end of the compressed stream has been reached.

            Returns:
                True if the decompressor has reached the end of stream,
                False otherwise.
            """
            return self._d.eof

        @property
        def needs_input(self) -> bool:
            return self._d.needs_input

        @override
        def decompress(self, data: bytes, max_length: int = -1) -> bytes:
            """Decompresses a chunk of data.

            Args:
                data: The compressed bytes to decompress.

            Returns:
                Decompressed bytes.
            """
            self._check_window(data)
            try:
                return self._d.decompress(data, max_length)
            except (_module.ZstdError, EOFError) as exc:
                if self._window_limit is not None and "memory" in str(exc).lower():
                    raise ArchiveResourceLimitError(
                        "Zstandard window exceeds configured limit"
                    ) from exc
                raise BadZipFile("Invalid Zstandard data") from exc

        def _check_window(self, data: bytes) -> None:
            if self._head is None or self._window_limit is None:
                return
            self._head += data[: 16 - len(self._head)]
            window = _frame_window(self._head)
            if window is None:
                return
            self._head = None
            if window > self._window_limit:
                raise ArchiveResourceLimitError(
                    "Zstandard window exceeds configured limit"
                )

    compression_entry = CompressionEntry(
        compression_method=ZIP_ZSTANDARD,
        compressor_factory=_ZstdCompressor,
        decompressor_factory=_ZstdDecompressor,
    )
