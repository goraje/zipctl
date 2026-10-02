from __future__ import annotations

from typing_extensions import override

from zipctl.compression.methods import (
    ZIP_BZIP2,
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
)
from zipctl.exceptions import BadZipFile

try:
    import bz2

    class _BZ2Compressor(CompressorBase):
        """Wraps bz2.BZ2Compressor to satisfy CompressorBase.

        Attributes:
            _c: The underlying bz2.BZ2Compressor instance.
        """

        def __init__(self, level: int | None) -> None:
            """Initializes the compressor with an optional compression level.

            Args:
                level: The compression level passed to bz2.BZ2Compressor.
                    If None, the default compression level is used.
            """
            if level is not None:
                self._c: bz2.BZ2Compressor = bz2.BZ2Compressor(level)
            else:
                self._c = bz2.BZ2Compressor()

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

    class _BZ2Decompressor(DecompressorBase):
        """Wraps bz2.BZ2Decompressor to satisfy DecompressorBase.

        Attributes:
            _d: The underlying bz2.BZ2Decompressor instance.
        """

        def __init__(self) -> None:
            """Initializes the decompressor."""
            self._d: bz2.BZ2Decompressor = bz2.BZ2Decompressor()

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
        @override
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
            except (OSError, EOFError) as exc:
                raise BadZipFile("Invalid BZIP2 data") from exc

    compression_entry: CompressionEntry | None = CompressionEntry(
        compression_method=ZIP_BZIP2,
        compressor_factory=_BZ2Compressor,
        decompressor_factory=_BZ2Decompressor,
    )
except ImportError:
    compression_entry = None
