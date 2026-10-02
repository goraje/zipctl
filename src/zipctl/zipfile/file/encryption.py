"""Encryption settings for the entries of a ZipFile."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeAlias, cast

from typing_extensions import override

from zipctl.cryptography import WZ_AES, ZIP_CRYPTO
from zipctl.cryptography.aes import AesZipEncryptor
from zipctl.cryptography.zipcrypto import ZipCryptoEncryptor
from zipctl.exceptions import PasswordRequired
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.shared import MASK_ENCRYPTED

if TYPE_CHECKING:
    from zipctl.cryptography.base import BaseZipEncryptor

__all__ = [
    "INHERIT_ENCRYPTION",
    "EncryptionOverride",
    "EncryptionSettings",
    "ZipFileExtra",
    "require_bytes",
]


class _InheritEncryption:
    __slots__: tuple[str, ...] = ()

    @override
    def __repr__(self) -> str:
        return "INHERIT_ENCRYPTION"


INHERIT_ENCRYPTION = _InheritEncryption()
EncryptionOverride: TypeAlias = str | None | _InheritEncryption


@dataclass(frozen=True)
class ZipFileExtra:
    """Immutable extra options for :class:`ZipFile`.

    Attributes:
        force_wz_aes_version: Override the WinZip AES version written to the
            extra field (``1`` or ``2``). ``None`` selects the metadata-safe
            AES version 2. Version 1 exposes the plaintext CRC and should only
            be selected for compatibility with older tools.
        wz_aes_nbits: AES key size in bits (``128``, ``192``, or ``256``).
            Defaults to ``256``.
    """

    force_wz_aes_version: int | None = None
    wz_aes_nbits: int = 256

    def __post_init__(self) -> None:
        if self.force_wz_aes_version not in (None, 1, 2):
            raise ValueError("force_wz_aes_version must be 1 or 2")
        if self.wz_aes_nbits not in (128, 192, 256):
            raise ValueError("wz_aes_nbits must be 128, 192 or 256")


def require_bytes(name: str, value: object) -> None:
    """Raise ``TypeError`` unless *value* is ``bytes`` (or ``None``)."""
    if value is not None and not isinstance(value, bytes):
        raise TypeError(f"{name}: expected bytes, got {type(value).__name__}")


class EncryptionSettings:
    """An archive's default encryption, and its default password.

    The password is also what encrypted members are read with when a call
    names none.

    Attributes:
        method: ``WZ_AES``, ``ZIP_CRYPTO`` or ``None`` for new entries.
        password: The default password, or ``None``.
    """

    def __init__(self, method: str | None, extra: ZipFileExtra | None) -> None:
        self.method: str | None = method
        self.password: bytes | None = None
        self._extra: ZipFileExtra = extra or ZipFileExtra()

    def encryptor(
        self,
        method: str | None = None,
        password: bytes | None = None,
        *,
        nbits: int | None = None,
        force_wz_aes_version: int | None = None,
    ) -> BaseZipEncryptor:
        """An encryptor for *method* (default: :attr:`method`).

        Raises:
            PasswordRequired: If there is no password at all.
            ValueError: If the password is empty.
            NotImplementedError: If the method is unknown.
        """
        method = self.method if method is None else method
        pwd = self.password if password is None else password
        if pwd is None:
            raise PasswordRequired("Encrypted entries require a password")
        if method == WZ_AES:
            return AesZipEncryptor(
                pwd,
                nbits=self._extra.wz_aes_nbits if nbits is None else nbits,
                force_wz_aes_version=(
                    self._extra.force_wz_aes_version
                    if force_wz_aes_version is None
                    else force_wz_aes_version
                ),
            )
        if method == ZIP_CRYPTO:
            return ZipCryptoEncryptor(pwd)
        raise NotImplementedError(f"Unknown encryption method: {method!r}")

    def for_entry(
        self,
        zinfo: ZipInfo,
        encryption: EncryptionOverride,
        password: bytes | None,
        extra: ZipFileExtra | None,
    ) -> BaseZipEncryptor | None:
        """The encryptor for a new entry, or ``None`` if it is stored in clear.

        Marks *zinfo* encrypted when it is not.
        """
        method = self.method if encryption is INHERIT_ENCRYPTION else encryption
        if method is None and password is not None:
            raise ValueError("password cannot be used for an unencrypted entry")
        if not method:
            return None
        encryptor = self.encryptor(
            cast(str, method),
            password,
            nbits=extra.wz_aes_nbits if extra else None,
            force_wz_aes_version=extra.force_wz_aes_version if extra else None,
        )
        zinfo.flag_bits |= MASK_ENCRYPTED
        return encryptor
