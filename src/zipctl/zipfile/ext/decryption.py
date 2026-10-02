"""Choosing the decrypter of an entry that is being read."""

from __future__ import annotations

from zipctl.cryptography.aes import AesZipDecrypter
from zipctl.cryptography.base import BaseZipDecrypter
from zipctl.cryptography.zipcrypto import ZipCryptoDecrypter
from zipctl.exceptions import BadZipFile, PasswordRequired
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.io_wrappers import ClosableZipStream, read_exactly

__all__ = ["decrypter_class", "read_encryption_header"]


def decrypter_class(zinfo: ZipInfo) -> type[BaseZipDecrypter]:
    """The decrypter for an encrypted entry: WZ-AES if it says so, else ZipCrypto."""
    if zinfo.aes_extra.wz_aes_version is not None:
        return AesZipDecrypter
    return ZipCryptoDecrypter


def read_encryption_header(
    fileobj: ClosableZipStream, zinfo: ZipInfo, pwd: bytes | None
) -> tuple[type[BaseZipDecrypter], bytes]:
    """Read the encryption header of an encrypted entry.

    Returns the decrypter class and the header bytes.

    Raises:
        PasswordRequired: If *pwd* is empty.
        BadZipFile: If the header is truncated.
    """
    if not pwd:
        raise PasswordRequired(
            f"File {zinfo.filename!r} is encrypted, password required for extraction"
        )
    cls = decrypter_class(zinfo)
    try:
        header = read_exactly(fileobj, cls.header_length(zinfo))
    except EOFError as exc:
        raise BadZipFile("Truncated encryption header") from exc
    return cls, header
