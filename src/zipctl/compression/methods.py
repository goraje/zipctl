from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from typing_extensions import override

from zipctl.limits import ArchiveLimits

__all__ = [
    "BZIP2_VERSION",
    "LZMA_VERSION",
    "ZSTANDARD_VERSION",
    "ZIP_STORED",
    "ZIP_DEFLATED",
    "ZIP_BZIP2",
    "ZIP_LZMA",
    "ZIP_ZSTANDARD",
    "CompressorBase",
    "DecompressorBase",
    "CompressionEntry",
    "NoopCompressor",
    "NoopDecompressor",
]

# ---------------------------------------------------------------------------
# ZIP compression method IDs
# ---------------------------------------------------------------------------
ZIP_STORED = 0
ZIP_DEFLATED = 8
ZIP_BZIP2 = 12
ZIP_LZMA = 14
ZIP_ZSTANDARD = 93

# ---------------------------------------------------------------------------
# Minimum ZIP version-needed-to-extract for each compression method
# ---------------------------------------------------------------------------
BZIP2_VERSION = 46
LZMA_VERSION = 63
ZSTANDARD_VERSION = 63


class CompressorBase(ABC):
    """Abstract base class for all compressors."""

    @abstractmethod
    def compress(self, data: bytes) -> bytes:
        """Compresses a chunk of data.

        Args:
            data: The raw bytes to compress.

        Returns:
            Compressed bytes. May be empty if data is buffered internally.
        """
        ...

    @abstractmethod
    def flush(self) -> bytes:
        """Flushes any remaining buffered data and finalizes the stream."""
        ...


class NoopCompressor(CompressorBase):
    """Pass-through compressor used for ``ZIP_STORED`` entries."""

    @override
    def compress(self, data: bytes) -> bytes:
        return data

    @override
    def flush(self) -> bytes:
        return b""


class DecompressorBase(ABC):
    """Abstract base class defining the interface of every decompressor.

    A reader calls :meth:`decompress` with new input while :attr:`needs_input`
    is ``True`` and with ``b""`` while the decompressor still holds input or
    output of its own, until :attr:`eof`.

    Attributes:
        concatenated: The format allows several independent frames one after
            another (Zstandard), so the stream ends with its input rather than
            with the first frame; :attr:`eof` then means "at a frame boundary".
    """

    concatenated: bool = False

    @property
    def needs_input(self) -> bool:
        """Whether the decompressor wants more compressed input.

        ``False`` while it can still produce output from input it was given
        earlier; such a decompressor must override this.
        """
        return True

    def configure_limits(self, limits: ArchiveLimits) -> None:
        """Apply decoder budgets; custom codecs may override this hook."""
        del limits

    @property
    @abstractmethod
    def eof(self) -> bool:
        """Whether the end of the compressed stream has been reached.

        Returns:
            True if the decompressor has reached the end of stream,
            False otherwise.
        """
        ...

    @abstractmethod
    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        """Decompress a chunk of data."""
        ...


class NoopDecompressor(DecompressorBase):
    """Pass-through decompressor used for ``ZIP_STORED`` entries."""

    @property
    @override
    def eof(self) -> bool:
        return False

    @override
    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        return data if max_length < 0 else data[:max_length]


@dataclass(frozen=True)
class CompressionEntry:
    """Registry entry pairing a compressor and decompressor factory for a ZIP method.

    Attributes:
        compression_method: The ZIP compression method ID this entry handles.
        compressor_factory: Callable that accepts an optional compression level
            and returns a CompressorBase instance, or None.
        decompressor_factory: Callable that takes no arguments and returns a
            DecompressorBase instance, or None.
    """

    compression_method: int
    compressor_factory: Callable[[int | None], CompressorBase | None]
    decompressor_factory: Callable[[], DecompressorBase | None]
