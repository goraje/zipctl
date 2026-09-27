from __future__ import annotations

import io

import pytest
from typing_extensions import override

from ziplet.cryptography.base import BaseZipDecrypter, BaseZipEncryptor
from ziplet.exceptions import BadZipFile


class TestBaseZipDecrypter:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            BaseZipDecrypter()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_subclass_missing_decrypt_cannot_instantiate(self) -> None:
        class Incomplete(BaseZipDecrypter):  # pyright: ignore[reportImplicitAbstractClass]  # left incomplete on purpose
            @classmethod
            @override
            def header_length(cls, zinfo: object) -> int:
                return 0

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_subclass_missing_header_length_cannot_instantiate(self) -> None:
        class Incomplete(BaseZipDecrypter):  # pyright: ignore[reportImplicitAbstractClass]  # left incomplete on purpose
            @override
            def decrypt(self, data: bytes) -> bytes:
                return data

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_concrete_subclass_can_instantiate(self) -> None:
        class Concrete(BaseZipDecrypter):
            @override
            def decrypt(self, data: bytes) -> bytes:
                return data

            @classmethod
            @override
            def header_length(cls, zinfo: object) -> int:
                return 0

        obj = Concrete()
        assert obj.decrypt(b"hello") == b"hello"

    def test_decrypt_passthrough(self) -> None:
        class Concrete(BaseZipDecrypter):
            @override
            def decrypt(self, data: bytes) -> bytes:
                return data

            @classmethod
            @override
            def header_length(cls, zinfo: object) -> int:
                return 0

        assert Concrete().decrypt(b"\x00\x01\x02") == b"\x00\x01\x02"

    def test_finalize_default_checks_crc32(self) -> None:
        class Concrete(BaseZipDecrypter):
            @override
            def decrypt(self, data: bytes) -> bytes:
                return data

            @classmethod
            @override
            def header_length(cls, zinfo: object) -> int:
                return 0

        obj = Concrete()
        obj.finalize(123, 123, io.BytesIO())
        with pytest.raises(BadZipFile, match="Bad CRC-32"):
            obj.finalize(123, 456, io.BytesIO())
        obj.finalize(None, None, io.BytesIO())


class TestBaseZipEncryptor:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            BaseZipEncryptor()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_subclass_missing_encrypt_cannot_instantiate(self) -> None:
        class Incomplete(BaseZipEncryptor):  # pyright: ignore[reportImplicitAbstractClass]  # left incomplete on purpose
            @override
            def update_zipinfo(self, zipinfo: object) -> None:
                pass

            @override
            def encryption_header(self) -> bytes:
                return b""

            @override
            def flush(self) -> bytes:
                return b""

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_subclass_missing_update_zipinfo_cannot_instantiate(self) -> None:
        class Incomplete(BaseZipEncryptor):  # pyright: ignore[reportImplicitAbstractClass]  # left incomplete on purpose
            @override
            def encrypt(self, data: bytes) -> bytes:
                return data

            @override
            def encryption_header(self) -> bytes:
                return b""

            @override
            def flush(self) -> bytes:
                return b""

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_subclass_missing_flush_cannot_instantiate(self) -> None:
        class Incomplete(BaseZipEncryptor):  # pyright: ignore[reportImplicitAbstractClass]  # left incomplete on purpose
            @override
            def update_zipinfo(self, zipinfo: object) -> None:
                pass

            @override
            def encrypt(self, data: bytes) -> bytes:
                return data

            @override
            def encryption_header(self) -> bytes:
                return b""

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]  # ty: ignore[call-non-callable]  # pyright: ignore[reportAbstractUsage]  # the test proves it cannot be instantiated

    def test_concrete_subclass_can_instantiate(self) -> None:
        class Concrete(BaseZipEncryptor):
            @override
            def update_zipinfo(self, zipinfo: object) -> None:
                pass

            @override
            def encrypt(self, data: bytes) -> bytes:
                return data

            @override
            def encryption_header(self) -> bytes:
                return b"\x00"

            @override
            def flush(self) -> bytes:
                return b""

        obj = Concrete()
        assert obj.encrypt(b"data") == b"data"
        assert obj.encryption_header() == b"\x00"
        assert obj.flush() == b""
