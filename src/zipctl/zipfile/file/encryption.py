"""Encryption settings for the entries of a ZipFile."""

# Friend access inside the zipfile package (ruff exempts it via SLF001).
# pyright: reportPrivateUsage=false

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeAlias, cast

from typing_extensions import override

from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.shared import MASK_ENCRYPTED

if TYPE_CHECKING:
    from zipctl.cryptography.base import BaseZipEncryptor
    from zipctl.zipfile.file import ZipFile

__all__ = ["INHERIT_ENCRYPTION", "EncryptionOverride", "ZipFileExtra"]


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


def entry_encryptor(
    zf: ZipFile,
    zinfo: ZipInfo,
    encryption: EncryptionOverride,
    password: bytes | None,
    extra: ZipFileExtra | None,
) -> BaseZipEncryptor | None:
    """The encryptor for an entry, or ``None`` if it is stored unencrypted."""
    effective_encryption = (
        zf.encryption if encryption is INHERIT_ENCRYPTION else encryption
    )
    if effective_encryption is None and password is not None:
        raise ValueError("password cannot be used for an unencrypted entry")
    if not effective_encryption:
        return None
    zinfo.flag_bits |= MASK_ENCRYPTED
    return zf.get_encryptor(
        cast(str, effective_encryption),
        password,
        nbits=extra.wz_aes_nbits if extra else None,
        force_wz_aes_version=extra.force_wz_aes_version if extra else None,
    )
