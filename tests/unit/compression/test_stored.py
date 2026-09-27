from __future__ import annotations

from zipctl.compression import NoopCompressor, NoopDecompressor, stored
from zipctl.compression.methods import ZIP_STORED, CompressionEntry


class TestStoredCompressionEntry:
    def test_entry_is_compression_entry(self) -> None:
        assert isinstance(stored.compression_entry, CompressionEntry)

    def test_compression_method_is_zip_stored(self) -> None:
        assert stored.compression_entry.compression_method == ZIP_STORED

    def test_compressor_factory_returns_noop(self) -> None:
        assert isinstance(
            stored.compression_entry.compressor_factory(None), NoopCompressor
        )

    def test_compressor_factory_ignores_level(self) -> None:
        for level in (0, 1, 5, 9):
            assert isinstance(
                stored.compression_entry.compressor_factory(level), NoopCompressor
            )

    def test_decompressor_factory_returns_noop(self) -> None:
        assert isinstance(
            stored.compression_entry.decompressor_factory(), NoopDecompressor
        )
