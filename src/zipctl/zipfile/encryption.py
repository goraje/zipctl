"""The encryption scheme of an entry: which one it uses, and its ciphers.

Everything that ties a cipher to an entry lives here: the scheme an entry is
read with, the check byte and AES strength its decrypter needs, and what an
encrypted entry sets on its ``ZipInfo`` when it is written (the encryption
flag, the WinZip AES field, the ZipCrypto data descriptor).  The adapters in
:mod:`zipctl.cryptography` are cipher code only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypeAlias, cast

from typing_extensions import override

from zipctl.cryptography.aes import (
    WZ_AES,
    WZ_AES_DEFAULT_VERSION,
    WZ_AES_VENDOR_ID,
    AesKeyCache,
    AesZipDecrypter,
    AesZipEncryptor,
    aes_header_length,
)
from zipctl.cryptography.zipcrypto import (
    ZIP_CRYPTO,
    ZIP_CRYPTO_HEADER_LENGTH,
    ZipCryptoDecrypter,
    ZipCryptoEncryptor,
)
from zipctl.exceptions import BadZipFile, PasswordRequired
from zipctl.format import read_exactly
from zipctl.zipfile.info import WzAesExtra, ZipInfo
from zipctl.zipfile.io_wrappers import ClosableZipStream
from zipctl.zipfile.shared import MASK_ENCRYPTED, MASK_USE_DATA_DESCRIPTOR

__all__ = [
    "INHERIT_ENCRYPTION",
    "Decrypter",
    "EncryptionOverride",
    "EncryptionSettings",
    "Encryptor",
    "ZipFileExtra",
    "open_decrypter",
    "read_encryption_header",
    "require_bytes",
]


class Encryptor(Protocol):
    """Encrypts one entry's data as it is written."""

    def encryption_header(self) -> bytes:
        """The header written in front of the ciphertext."""
        ...

    def encrypt(self, data: bytes, /) -> bytes:
        """Encrypt a chunk; the result is as long as *data*."""
        ...

    def flush(self) -> bytes:
        """The authentication trailer written after the ciphertext, if any."""
        ...


class Decrypter(Protocol):
    """Decrypts one entry's data as it is read.

    :meth:`finalize` reads and checks the authentication trailer that
    follows the ciphertext.  Where ``authenticates_ciphertext`` is true that
    check alone proves the entry intact, with no need to decompress it.
    """

    @property
    def authenticates_ciphertext(self) -> bool: ...

    def decrypt(self, data: bytes, /) -> bytes:
        """Decrypt a chunk; the result is as long as *data*."""
        ...

    def finalize(self, fileobj: ClosableZipStream, /) -> None:
        """Check the authentication trailer, read from *fileobj*."""
        ...


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


def _checked_method(method: str | None) -> str | None:
    """Return *method*, refusing anything but ``WZ_AES``, ``ZIP_CRYPTO`` or ``None``."""
    if method not in (None, WZ_AES, ZIP_CRYPTO):
        raise ValueError(f"Unknown encryption method: {method!r}")
    return method


class EncryptionSettings:
    """An archive's default encryption, and its default password.

    The password is also what encrypted members are read with when a call
    names none.

    Attributes:
        method: ``WZ_AES``, ``ZIP_CRYPTO`` or ``None`` for new entries.
        password: The default password, or ``None``.
    """

    def __init__(self, method: str | None, extra: ZipFileExtra | None) -> None:
        self._method: str | None = _checked_method(method)
        self.password: bytes | None = None
        self._extra: ZipFileExtra = extra or ZipFileExtra()

    @property
    def method(self) -> str | None:
        return self._method

    @method.setter
    def method(self, method: str | None) -> None:
        self._method = _checked_method(method)

    def for_entry(
        self,
        zinfo: ZipInfo,
        encryption: EncryptionOverride,
        password: bytes | None,
        extra: ZipFileExtra | None,
    ) -> Encryptor | None:
        """The encryptor for a new entry, or ``None`` if it is stored in clear.

        Marks *zinfo* encrypted, with the fields its scheme needs: the WinZip
        AES field, or for ZipCrypto a data descriptor, since the header is then
        checked against the time rather than a CRC not yet known.

        Raises:
            PasswordRequired: If there is no password at all.
            ValueError: If the password is empty, or given for an entry
                stored in clear.
        """
        if encryption is not INHERIT_ENCRYPTION:
            method = encryption
        elif zinfo.is_dir():  # a directory has no data to protect
            method = None
        else:
            method = self.method
        _checked_method(cast("str | None", method))
        if method is None and password is not None:
            raise ValueError("password cannot be used for an unencrypted entry")
        if not method:
            return None
        pwd = self.password if password is None else password
        if pwd is None:
            raise PasswordRequired("Encrypted entries require a password")
        require_bytes("password", pwd)
        encryptor: Encryptor
        if method == WZ_AES:
            aes = AesZipEncryptor(pwd, (extra or self._extra).wz_aes_nbits)
            # a per-entry extra without a version takes the archive's
            version = (
                (extra.force_wz_aes_version if extra else None)
                or self._extra.force_wz_aes_version
                or WZ_AES_DEFAULT_VERSION
            )
            zinfo.aes_extra = WzAesExtra(version, WZ_AES_VENDOR_ID, aes.strength)
            encryptor = aes
        else:
            # the check byte comes from the DOS time, as the CRC is not known yet
            encryptor = ZipCryptoEncryptor(pwd, (zinfo.get_dostime() >> 8) & 0xFF)
            zinfo.flag_bits |= MASK_USE_DATA_DESCRIPTOR
        zinfo.flag_bits |= MASK_ENCRYPTED
        return encryptor


def read_encryption_header(
    fileobj: ClosableZipStream, zinfo: ZipInfo, pwd: bytes | None
) -> tuple[bytes, int]:
    """Read the encryption header in front of an encrypted entry's data.

    Returns the header, and the length of the authentication trailer that
    follows the ciphertext.

    Raises:
        PasswordRequired: If *pwd* is empty.
        BadZipFile: If the header is truncated.
    """
    if not pwd:
        raise PasswordRequired(
            f"File {zinfo.filename!r} is encrypted, password required for extraction"
        )
    aes = zinfo.aes_extra
    if aes is None:
        length, trailer_length = ZIP_CRYPTO_HEADER_LENGTH, 0
    else:
        length = aes_header_length(aes.wz_aes_strength)
        trailer_length = AesZipDecrypter.hmac_size
    try:
        return read_exactly(fileobj, length), trailer_length
    except EOFError as exc:
        raise BadZipFile("Truncated encryption header") from exc


def open_decrypter(
    zinfo: ZipInfo,
    pwd: bytes,
    encryption_header: bytes,
    dos_time: int,
    key_cache: AesKeyCache | None = None,
) -> Decrypter:
    """The decrypter for an encrypted entry, once *pwd* passes its header check.

    WinZip AES if the entry says so, else ZipCrypto.  *dos_time* is the DOS
    time stored in the entry's headers, which ``date_time`` may no longer
    match.  *key_cache* keeps derived AES keys across the decrypters of one
    archive.

    Raises:
        BadPassword: If the header's verifier rejects *pwd*.
    """
    if zinfo.aes_extra is not None:
        return AesZipDecrypter(
            pwd,
            encryption_header,
            zinfo.aes_extra.wz_aes_strength,
            zinfo.filename,
            key_cache,
        )
    # ZipCrypto's check byte is the high byte of the CRC, or of the DOS time
    # where a data descriptor carries the CRC.
    if zinfo.use_data_descriptor:
        check_byte = (dos_time >> 8) & 0xFF
    else:
        check_byte = (zinfo.CRC >> 24) & 0xFF
    return ZipCryptoDecrypter(pwd, encryption_header, check_byte, zinfo.filename)
