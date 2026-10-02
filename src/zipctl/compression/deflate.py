from __future__ import annotations

from typing_extensions import override

from zipctl.compression.methods import (
    ZIP_DEFLATED,
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
)
from zipctl.exceptions import BadZipFile

try:
    import zlib

    class _ZlibCompressor(CompressorBase):
        """Wraps zlib.compressobj to satisfy CompressorBase.

        Uses raw deflate format (wbits=-15) as required by the ZIP specification.

        Attributes:
            _c: The underlying zlib Compress object.
        """

        def __init__(self, level: int | None) -> None:
            """Initializes the compressor with an optional compression level.

            Args:
                level: The zlib compression level (0-9). If None, the zlib
                    default compression level is used.
            """
            if level is not None:
                # typeshed only exposes the object type under a private name
                self._c: zlib._Compress = zlib.compressobj(  # pyright: ignore[reportPrivateUsage]
                    level, zlib.DEFLATED, -15
                )
            else:
                self._c = zlib.compressobj(
                    zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15
                )

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

    class _ZlibDecompressor(DecompressorBase):
        """Wraps zlib.decompressobj to satisfy DecompressorBase.

        Uses raw deflate format (wbits=-15) as required by the ZIP specification.
        Input left over by a bounded call is kept and decompressed first next
        time, so :attr:`needs_input` is ``False`` until it is used up.

        Attributes:
            _d: The underlying zlib Decompress object.
        """

        def __init__(self) -> None:
            """Initializes the decompressor."""
            # typeshed only exposes the object type under a private name
            self._d: zlib._Decompress = zlib.decompressobj(  # pyright: ignore[reportPrivateUsage]
                -15
            )

        @property
        @override
        def eof(self) -> bool:
            return self._d.eof

        @property
        @override
        def needs_input(self) -> bool:
            return not self._d.unconsumed_tail

        @override
        def decompress(self, data: bytes, max_length: int = -1) -> bytes:
            """Decompresses left-over input and then *data*.

            Args:
                data: The compressed bytes to decompress.
                max_length: Maximum number of bytes to return. If negative,
                    there is no limit on the output size.

            Returns:
                Decompressed bytes, up to max_length bytes if specified.
            """
            try:
                return self._d.decompress(
                    self._d.unconsumed_tail + data, max(0, max_length)
                )
            except zlib.error as exc:
                raise BadZipFile("Invalid DEFLATE data") from exc

    compression_entry: CompressionEntry | None = CompressionEntry(
        compression_method=ZIP_DEFLATED,
        compressor_factory=_ZlibCompressor,
        decompressor_factory=_ZlibDecompressor,
    )
except ImportError:
    compression_entry = None
