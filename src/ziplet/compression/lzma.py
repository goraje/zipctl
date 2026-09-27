from __future__ import annotations

import struct

from typing_extensions import override

from ziplet.compression.methods import (
    ZIP_LZMA,
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
)
from ziplet.exceptions import BadZipFile

_MAX_LZMA_DICT_SIZE = 1 << 30

try:
    import lzma

    _LZMA1_LC: int = 3
    _LZMA1_LP: int = 0
    _LZMA1_PB: int = 2
    _LZMA1_DICT_SIZE: int = 8_388_608

    def _lzma1_props_bytes() -> bytes:
        """Encodes the default LZMA1 filter parameters into a properties byte sequence.

        Computes the single properties byte from the module-level ``lc``, ``lp``,
        and ``pb`` constants using the formula defined in the LZMA specification
        (``props_byte = (pb * 5 + lp) * 9 + lc``), then appends ``dict_size`` as
        a 4-byte little-endian integer.

        Returns:
            A 5-byte sequence: 1 properties byte followed by 4 bytes of
            dictionary size in little-endian order.
        """
        props_byte = (_LZMA1_PB * 5 + _LZMA1_LP) * 9 + _LZMA1_LC
        return bytes([props_byte]) + struct.pack("<I", _LZMA1_DICT_SIZE)

    def _lzma1_filter_from_props(props: bytes) -> dict[str, int]:
        """Decodes an LZMA1 properties byte sequence into an lzma filter dict.

        Reverses the encoding performed by ``_lzma1_props_bytes``: extracts
        ``lc``, ``lp``, and ``pb`` from the first byte using the inverse LZMA
        spec formulas, and reads ``dict_size`` from the following 4-byte
        little-endian integer.

        Args:
            props: A 5-byte sequence as produced by ``_lzma1_props_bytes`` or
                read from a ZIP LZMA stream header.

        Returns:
            A filter parameter dict suitable for passing as an element of the
            ``filters`` argument to ``lzma.LZMACompressor`` or
            ``lzma.LZMADecompressor`` with ``FORMAT_RAW``.
        """
        if len(props) != 5:
            raise BadZipFile("Invalid LZMA properties")
        props_byte = props[0]
        lc = props_byte % 9
        lp = (props_byte // 9) % 5
        pb = props_byte // 45
        if lc > 8 or lp > 4 or pb > 4 or lc + lp > 4:
            raise BadZipFile("Invalid LZMA properties")
        (dict_size,) = struct.unpack("<I", props[1:5])
        if dict_size > _MAX_LZMA_DICT_SIZE:
            raise BadZipFile(
                f"LZMA dictionary size {dict_size} exceeds the supported limit "
                f"of {_MAX_LZMA_DICT_SIZE} bytes"
            )
        return {
            "id": lzma.FILTER_LZMA1,
            "lc": lc,
            "lp": lp,
            "pb": pb,
            "dict_size": dict_size,
        }

    class _LZMACompressor(CompressorBase):
        """Compressor for the ZIP LZMA (method 14) format.

        Lazily initializes the underlying lzma.LZMACompressor on the first
        call to compress() or flush(), prepending the LZMA properties header
        required by the ZIP specification.

        Attributes:
            _comp: The underlying lzma.LZMACompressor, or None before the
                first compress/flush call.
        """

        def __init__(self) -> None:
            """Initializes the compressor in a deferred state."""
            self._comp: lzma.LZMACompressor | None = None

        def _init(self) -> tuple[bytes, lzma.LZMACompressor]:
            """Initializes the underlying compressor and builds the ZIP LZMA header.

            Encodes the LZMA1 filter properties and constructs the 4-byte
            version/properties header required by the ZIP LZMA specification.

            Returns:
                A (header, compressor) tuple. The header bytes are prepended to
                the compressed stream; the compressor is the initialized instance.
            """
            props = _lzma1_props_bytes()
            comp = lzma.LZMACompressor(
                lzma.FORMAT_RAW,
                filters=[_lzma1_filter_from_props(props)],
            )
            self._comp = comp
            return struct.pack("<BBH", 9, 4, len(props)) + props, comp

        @override
        def compress(self, data: bytes) -> bytes:
            """Compresses a chunk of data.

            On the first call, initializes the compressor and prepends the
            ZIP LZMA header to the output.

            Args:
                data: The raw bytes to compress.

            Returns:
                Compressed bytes, prefixed with the LZMA header on the first
                call. May be empty if data is buffered internally.
            """
            if self._comp is None:
                header, comp = self._init()
                return header + comp.compress(data)
            return self._comp.compress(data)

        @override
        def flush(self) -> bytes:
            """Flushes any remaining buffered data and finalizes the stream.

            On the first call (if compress() was never called), initializes
            the compressor and prepends the ZIP LZMA header.

            Returns:
                The remaining compressed bytes, prefixed with the LZMA header
                if the compressor had not yet been initialized.
            """
            if self._comp is None:
                header, comp = self._init()
                return header + comp.flush()
            return self._comp.flush()

    class _LZMADecompressor(DecompressorBase):
        """Decompressor for the ZIP LZMA (method 14) format.

        Buffers incoming data until the ZIP LZMA header (version, flags, and
        filter properties) has been fully received, then initializes the
        underlying lzma.LZMADecompressor and begins producing output.

        Attributes:
            _decomp: The underlying lzma.LZMADecompressor, or None while the
                header is still being buffered.
            _unconsumed: Buffer that accumulates header bytes before the
                decompressor is initialized.
            _eof: Tracks whether the end of the compressed stream has been
                reached.
        """

        def __init__(self) -> None:
            """Initializes the decompressor in a deferred state."""
            self._decomp: lzma.LZMADecompressor | None = None
            self._unconsumed: bytes = b""
            self._eof: bool = False

        @property
        @override
        def eof(self) -> bool:
            """Whether the end of the compressed stream has been reached.

            Returns:
                True if the decompressor has reached the end of stream,
                False otherwise.
            """
            return self._eof

        @property
        def needs_input(self) -> bool:
            return self._decomp is None or self._decomp.needs_input

        @override
        def decompress(self, data: bytes, max_length: int = -1) -> bytes:
            """Decompresses a chunk of data.

            Accumulates data until the ZIP LZMA header is complete, then
            initializes the underlying decompressor and decompresses the
            remaining payload bytes.

            Args:
                data: The compressed bytes to decompress, which may include
                    header bytes on the first call(s).

            Returns:
                Decompressed bytes, or an empty bytes object if the header
                has not yet been fully received.
            """
            if self._decomp is None:
                self._unconsumed += data
                if len(self._unconsumed) < 4:
                    return b""
                if self._unconsumed[:2] != b"\x09\x04":
                    raise BadZipFile("Invalid ZIP LZMA header")
                (psize,) = struct.unpack("<H", self._unconsumed[2:4])
                if psize != 5:
                    raise BadZipFile("Invalid ZIP LZMA properties size")
                if len(self._unconsumed) < 4 + psize:
                    return b""
                self._decomp = lzma.LZMADecompressor(
                    lzma.FORMAT_RAW,
                    filters=[_lzma1_filter_from_props(self._unconsumed[4 : 4 + psize])],
                )
                data = self._unconsumed[4 + psize :]
                del self._unconsumed

            assert self._decomp is not None
            result = self._decomp.decompress(data, max_length)
            self._eof = self._decomp.eof
            return result

    def _lzma_decompressor() -> DecompressorBase:
        """Factory function that creates an LZMA decompressor.

        Returns:
            A new _LZMADecompressor instance.
        """
        return _LZMADecompressor()

    compression_entry: CompressionEntry | None = CompressionEntry(
        compression_method=ZIP_LZMA,
        compressor_factory=lambda _level: _LZMACompressor(),
        decompressor_factory=_lzma_decompressor,
    )
except ImportError:
    compression_entry = None
