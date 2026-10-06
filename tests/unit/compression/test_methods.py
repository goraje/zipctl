from __future__ import annotations

import pytest
from typing_extensions import override

from zipctl.compression.methods import (
    CompressorBase,
    DecompressorBase,
)


class TestCompressorBase:
    def test_concrete_subclass_requires_compress_and_flush(self) -> None:
        class _Incomplete(CompressorBase):  # pyright: ignore[reportImplicitAbstractClass]  # left incomplete on purpose
            @override
            def compress(self, data: bytes) -> bytes:
                return data

        with pytest.raises(TypeError):
            _Incomplete()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated


class TestDecompressorBase:
    def test_concrete_subclass_requires_decompress_and_finish(self) -> None:
        class _Incomplete(DecompressorBase):  # pyright: ignore[reportImplicitAbstractClass]  # left incomplete on purpose
            @override
            def finish(self) -> None:
                pass

        with pytest.raises(TypeError):
            _Incomplete()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated


def test_decompressor_wants_input_by_default() -> None:
    class _Passthrough(DecompressorBase):
        @override
        def decompress(self, data: bytes, max_length: int = -1) -> bytes:
            return data

        @override
        def finish(self) -> None:
            pass

    d = _Passthrough()
    assert d.needs_input
