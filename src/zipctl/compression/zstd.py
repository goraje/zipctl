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
            try:
                return self._d.decompress(data, max_length)
            except (_module.ZstdError, EOFError) as exc:
                if self._window_limit is not None and "memory" in str(exc).lower():
                    raise ArchiveResourceLimitError(
                        "Zstandard window exceeds configured limit"
                    ) from exc
                raise BadZipFile("Invalid Zstandard data") from exc

    compression_entry = CompressionEntry(
        compression_method=ZIP_ZSTANDARD,
        compressor_factory=_ZstdCompressor,
        decompressor_factory=_ZstdDecompressor,
    )
