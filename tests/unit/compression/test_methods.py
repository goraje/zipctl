from __future__ import annotations

import pytest
from typing_extensions import override

from zipctl.compression.methods import (
    CompressorBase,
    DecompressorBase,
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


def test_decompressor_wants_input_by_default() -> None:
    class _Passthrough(DecompressorBase):
        @property
        @override
        def eof(self) -> bool:
            return False

        @override
        def decompress(self, data: bytes, max_length: int = -1) -> bytes:
            return data

    d = _Passthrough()
    assert d.needs_input
    assert not d.concatenated
