from __future__ import annotations

from zipctl.compression.methods import (
    ZIP_STORED,
    CompressionEntry,
    NoopCompressor,
    NoopDecompressor,
)

compression_entry: CompressionEntry = CompressionEntry(
    compression_method=ZIP_STORED,
    compressor_factory=lambda _level: NoopCompressor(),
    decompressor_factory=lambda _flags, _limits: NoopDecompressor(),
)
