from __future__ import annotations

import importlib
import sys
from typing import cast
from unittest import mock
from unittest.mock import MagicMock

import pytest
from typing_extensions import override

from zipctl.compression import (
    ZIP_BZIP2,
    ZIP_DEFLATED,
    ZIP_LZMA,
    ZIP_STORED,
    ZIP_ZSTANDARD,
    CompressionEntry,
    CompressorBase,
    NoopCompressor,
    NoopDecompressor,
    Registry,
    deflate,
    registry,
)


class TestRegistryCheckCompression:
    def test_unknown_method_raises_not_implemented(self) -> None:
        r = Registry()
        with pytest.raises(NotImplementedError):
            r.check_compression(9999)

    def test_missing_zlib_raises_runtime_error(self) -> None:
        r = Registry()
        # Remove deflate from registry to simulate missing zlib
        r._registry.pop(ZIP_DEFLATED, None)
        with pytest.raises(RuntimeError, match="zlib"):
            r.check_compression(ZIP_DEFLATED)

    def test_missing_bz2_raises_runtime_error(self) -> None:
        r = Registry()
        r._registry.pop(ZIP_BZIP2, None)
        with pytest.raises(RuntimeError, match="bz2"):
            r.check_compression(ZIP_BZIP2)

    def test_missing_lzma_raises_runtime_error(self) -> None:
        r = Registry()
        r._registry.pop(ZIP_LZMA, None)
        with pytest.raises(RuntimeError, match="lzma"):
            r.check_compression(ZIP_LZMA)

    def test_missing_zstd_raises_runtime_error(self) -> None:
        r = Registry()
        r._registry.pop(ZIP_ZSTANDARD, None)
        with pytest.raises(RuntimeError, match="compression.zstd"):
            r.check_compression(ZIP_ZSTANDARD)

    def test_registered_method_does_not_raise(self) -> None:
        r = Registry()
        r.check_compression(ZIP_STORED)  # no exception


class TestRegistryRegister:
    def test_copy_is_independent(self) -> None:
        original = Registry()
        copied = original.copy()
        copied._registry.clear()
        assert original._registry

    def test_register_custom_entry(self) -> None:
        r = Registry()
        mock_compressor = MagicMock(spec=CompressorBase)
        custom_entry = CompressionEntry(
            compression_method=999,
            compressor_factory=lambda _level: mock_compressor,
            decompressor_factory=lambda: None,
        )
        r.register(999, custom_entry)
        r.check_compression(999)  # should not raise

    def test_register_overrides_existing_entry(self) -> None:
        r = Registry()

        class _SentinelCompressor(CompressorBase):
            @override
            def compress(self, data: bytes) -> bytes:
                return data

            @override
            def flush(self) -> bytes:
                return b""

        sentinel = _SentinelCompressor()
        new_entry = CompressionEntry(
            compression_method=ZIP_STORED,
            compressor_factory=lambda _level: sentinel,
            decompressor_factory=lambda: None,
        )
        r.register(ZIP_STORED, new_entry)
        result = r.get_compressor(ZIP_STORED)
        assert result is sentinel


class TestRegistryGetCompressor:
    def test_stored_returns_noop_compressor(self) -> None:
        r = Registry()
        assert isinstance(r.get_compressor(ZIP_STORED), NoopCompressor)

    def test_stored_returns_noop_compressor_with_level(self) -> None:
        r = Registry()
        assert isinstance(r.get_compressor(ZIP_STORED, compresslevel=9), NoopCompressor)

    def test_deflate_returns_compressor_with_level(self) -> None:
        if deflate.compression_entry is None:
            pytest.skip("zlib not available")
        r = Registry()
        c = r.get_compressor(ZIP_DEFLATED, compresslevel=6)
        assert isinstance(c, CompressorBase)

    def test_unknown_method_raises(self) -> None:
        r = Registry()
        with pytest.raises(NotImplementedError):
            r.get_compressor(9999)


class TestRegistryGetDecompressor:
    def test_stored_returns_noop_decompressor(self) -> None:
        r = Registry()
        assert isinstance(r.get_decompressor(ZIP_STORED), NoopDecompressor)

    def test_unknown_method_raises(self) -> None:
        r = Registry()
        with pytest.raises(NotImplementedError):
            r.get_decompressor(9999)

    def test_each_call_returns_fresh_instance(self) -> None:
        if deflate.compression_entry is None:
            pytest.skip("zlib not available")
        r = Registry()
        d1 = r.get_decompressor(ZIP_DEFLATED)
        d2 = r.get_decompressor(ZIP_DEFLATED)
        assert d1 is not d2


class TestSubmoduleImport:
    """Verify that each compression submodule sets compression_entry = None
    when its backing stdlib module is unavailable at import time."""

    @pytest.mark.parametrize(
        ("method", "backing_module", "submodule"),
        [
            (ZIP_DEFLATED, "zlib", "zipctl.compression.deflate"),
            (ZIP_BZIP2, "bz2", "zipctl.compression.bz2"),
            (ZIP_LZMA, "lzma", "zipctl.compression.lzma"),
        ],
    )
    def test_skips_registration_when_backing_module_absent(
        self, method: int, backing_module: str, submodule: str
    ) -> None:
        """Re-execute submodule import with backing stdlib module blocked.

        This simulates ImportError at import time. The submodule must expose
        compression_entry as None and must not register the method globally.
        """
        saved_entry = registry._registry.pop(method, None)
        sys.modules.pop(submodule, None)
        try:
            # Setting an entry to None in sys.modules makes import raise
            # ImportError for that module name.
            with mock.patch.dict(sys.modules, {backing_module: None}):
                mod = importlib.import_module(submodule)
                entry = cast("CompressionEntry | None", mod.compression_entry)
                assert entry is None, (
                    f"{submodule}.compression_entry should be None when "
                    f"{backing_module} is unavailable"
                )
                assert method not in registry._registry, (
                    f"{submodule} registered method {method} even though "
                    f"{backing_module} is unavailable"
                )
        finally:
            if saved_entry is not None:
                registry._registry[method] = saved_entry
            sys.modules.pop(submodule, None)
            importlib.import_module(submodule)
