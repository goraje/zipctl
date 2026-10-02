"""Encryption headers and decrypters for an entry that is being read."""

from __future__ import annotations

from zipctl.cryptography.aes import AesKeyCache, AesZipDecrypter
from zipctl.cryptography.zipcrypto import ZipCryptoDecrypter
from zipctl.exceptions import BadZipFile, PasswordRequired
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.io_wrappers import ClosableZipStream, read_exactly

__all__ = ["make_decrypter", "read_encryption_header", "read_header"]


def read_header(fileobj: ClosableZipStream, size: int, method: str) -> bytes:
    """Read *size* bytes of *method* framing, or raise ``BadZipFile`` if cut short."""
    try:
        return read_exactly(fileobj, size)
    except EOFError as exc:
        raise BadZipFile(f"Truncated {method} encryption header") from exc


def read_encryption_header(
    fileobj: ClosableZipStream, zinfo: ZipInfo, pwd: bytes | None
) -> tuple[type[ZipCryptoDecrypter | AesZipDecrypter], bytes, int]:
    """Read the encryption header of an encrypted entry.

    Returns the decrypter class, the header bytes, and how many bytes of the
    the compressed bytes the header and any authentication trailer take.

    Raises:
        PasswordRequired: If *pwd* is empty.
        BadZipFile: If the header is truncated.
    """
    name = zinfo.filename
    if zinfo.aes_extra.wz_aes_version is not None:
        if not pwd:
            raise PasswordRequired(
                f"File {name!r} is encrypted with WZ_AES encryption and "
                "requires a password."
            )
        length = AesZipDecrypter.header_length(zinfo)
        header = read_header(fileobj, length, "AES")
        overhead = length + AesZipDecrypter.authentication_trailer_length
        return AesZipDecrypter, header, overhead
    if not pwd:
        raise PasswordRequired(
            f"File {name!r} is encrypted, password required for extraction"
        )
    header = read_header(
        fileobj, ZipCryptoDecrypter.encryption_header_length, "ZipCrypto"
    )
    overhead = ZipCryptoDecrypter.header_length(zinfo)
    return ZipCryptoDecrypter, header, overhead


def make_decrypter(
    cls: type[ZipCryptoDecrypter | AesZipDecrypter],
    zinfo: ZipInfo,
    pwd: bytes,
    header: bytes,
    key_cache: AesKeyCache | None,
) -> ZipCryptoDecrypter | AesZipDecrypter:
    """Build a decrypter, which raises ``BadPassword`` if the verifier rejects *pwd*."""
    if cls is AesZipDecrypter:
        return AesZipDecrypter(zinfo, pwd, header, key_cache)
    return ZipCryptoDecrypter(zinfo, pwd, header)
