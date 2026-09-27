from __future__ import annotations

import pytest
from typing_extensions import override

from ziplet.compression.methods import (
    CompressionEntry,
    CompressorBase,
    DecompressorBase,
    StreamingDecompressor,
)


class TestCompressorBase:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            CompressorBase()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_concrete_subclass_requires_compress_and_flush(self) -> None:
        class _Incomplete(CompressorBase):  # pyright: ignore[reportImplicitAbstractClass]  # left incomplete on purpose
            @override
            def compress(self, data: bytes) -> bytes:
                return data

        with pytest.raises(TypeError):
            _Incomplete()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_concrete_subclass_works(self) -> None:
        class _Passthrough(CompressorBase):
            @override
            def compress(self, data: bytes) -> bytes:
                return data

            @override
            def flush(self) -> bytes:
                return b""

        c = _Passthrough()
        assert c.compress(b"hello") == b"hello"
        assert c.flush() == b""


class TestDecompressorBase:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            DecompressorBase()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_concrete_subclass_requires_eof_and_decompress(self) -> None:
        class _Incomplete(DecompressorBase):  # pyright: ignore[reportImplicitAbstractClass]  # left incomplete on purpose
            @property
            @override
            def eof(self) -> bool:
                return False

        with pytest.raises(TypeError):
            _Incomplete()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_concrete_subclass_works(self) -> None:
        class _Passthrough(DecompressorBase):
            @property
            @override
            def eof(self) -> bool:
                return True

            @override
            def decompress(self, data: bytes, max_length: int = -1) -> bytes:
                return data

        d = _Passthrough()
        assert d.eof is True
        assert d.decompress(b"hello") == b"hello"


class TestStreamingDecompressor:
    def test_is_subclass_of_decompressor_base(self) -> None:
        assert issubclass(StreamingDecompressor, DecompressorBase)

    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            StreamingDecompressor()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_concrete_subclass_works(self) -> None:
        class _PassthroughStreaming(StreamingDecompressor):
            @property
            @override
            def eof(self) -> bool:
                return False

            @property
            @override
            def unconsumed_tail(self) -> bytes:
                return b""

            @override
            def flush(self) -> bytes:
                return b""

            @override
            def decompress(self, data: bytes, max_length: int = -1) -> bytes:
                return data if max_length < 0 else data[:max_length]

        d = _PassthroughStreaming()
        assert d.eof is False
        assert d.unconsumed_tail == b""
        assert d.flush() == b""
        assert d.decompress(b"hello") == b"hello"
        assert (
            d.decompress(b"hello", max_length=3) == b"hel"  # spellchecker:disable-line
        )


class TestCompressionEntry:
    def test_is_frozen_dataclass(self) -> None:
        entry = CompressionEntry(
            compression_method=0,
            compressor_factory=lambda _level: None,
            decompressor_factory=lambda: None,
        )
        with pytest.raises((AttributeError, TypeError)):
            entry.compression_method = 99  # type: ignore[misc]  # ty: ignore[invalid-assignment]  # pyright: ignore[reportAttributeAccessIssue]  # the test proves the dataclass is frozen

    def test_fields_accessible(self) -> None:
        def factory_c(_level: int | None) -> CompressorBase | None:
            return None

        def factory_d() -> DecompressorBase | None:
            return None

        entry = CompressionEntry(
            compression_method=42,
            compressor_factory=factory_c,
            decompressor_factory=factory_d,
        )
        assert entry.compression_method == 42
        assert entry.compressor_factory is factory_c
        assert entry.decompressor_factory is factory_d

    def test_compressor_factory_called(self) -> None:
        class _DummyCompressor(CompressorBase):
            @override
            def compress(self, data: bytes) -> bytes:
                return data

            @override
            def flush(self) -> bytes:
                return b""

        class _DummyDecompressor(DecompressorBase):
            @property
            @override
            def eof(self) -> bool:
                return True

            @override
            def decompress(self, data: bytes, max_length: int = -1) -> bytes:
                return data

        compressor = _DummyCompressor()
        decompressor = _DummyDecompressor()
        entry = CompressionEntry(
            compression_method=0,
            compressor_factory=lambda _level: compressor,
            decompressor_factory=lambda: decompressor,
        )
        assert entry.compressor_factory(5) is compressor
        assert entry.decompressor_factory() is decompressor
