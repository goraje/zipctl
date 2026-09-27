from __future__ import annotations

from typing_extensions import override

from zipctl.compression.methods import (
    ZIP_DEFLATED,
    CompressionEntry,
    CompressorBase,
    StreamingDecompressor,
)

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

    class _ZlibDecompressor(StreamingDecompressor):
        """Wraps zlib.decompressobj to satisfy StreamingDecompressor.

        Uses raw deflate format (wbits=-15) as required by the ZIP specification.

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
            """Whether the end of the compressed stream has been reached.

            Returns:
                True if the decompressor has reached the end of stream,
                False otherwise.
            """
            return self._d.eof

        @property
        @override
        def unconsumed_tail(self) -> bytes:
            """Data that was not consumed during the last decompress call.

            Returns:
                Bytes that were passed to decompress but not yet processed
                due to a max_length limit.
            """
            return self._d.unconsumed_tail

        @property
        @override
        def needs_input(self) -> bool:
            return not self._d.unconsumed_tail

        @override
        def decompress(self, data: bytes, max_length: int = -1) -> bytes:
            """Decompresses a chunk of data.

            Args:
                data: The compressed bytes to decompress.
                max_length: Maximum number of bytes to return. If negative,
                    there is no limit on the output size.

            Returns:
                Decompressed bytes, up to max_length bytes if specified.
            """
            if max_length < 0:
                return self._d.decompress(data)
            return self._d.decompress(data, max_length)

        @override
        def flush(self) -> bytes:
            """Flushes any remaining buffered data.

            Returns:
                Any remaining decompressed bytes.
            """
            return self._d.flush()

    compression_entry: CompressionEntry | None = CompressionEntry(
        compression_method=ZIP_DEFLATED,
        compressor_factory=_ZlibCompressor,
        decompressor_factory=_ZlibDecompressor,
    )
except ImportError:
    compression_entry = None
