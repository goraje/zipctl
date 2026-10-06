# SPDX-License-Identifier: MIT
# Derived in part from pyzipper (see NOTICE and licenses/pyzipper-MIT.txt).
"""Traditional ZipCrypto (PKWARE) encryption and decryption for ZIP archives.

Implements the original ZIP stream cipher described in the PKWARE Application
Note. The algorithm maintains three 32-bit keys updated with each byte
processed, derived from a CRC32-based key schedule.

Note:
    ZipCrypto provides only weak security. Prefer WZ-AES for new archives.
"""

from __future__ import annotations

import os

from zipctl.exceptions import BadPassword, BadZipFile

__all__ = [
    "ZIP_CRYPTO",
    "ZIP_CRYPTO_HEADER_LENGTH",
    "ZipCryptoDecrypter",
    "ZipCryptoEncryptor",
]

ZIP_CRYPTO = "ZipCrypto"

ZIP_CRYPTO_HEADER_LENGTH = 12


def _gen_crc(crc: int) -> int:
    """Compute one entry of the CRC32 lookup table.

    Args:
        crc (int): Seed value (0–255) for the table entry.

    Returns:
        int: The 32-bit CRC table value for *crc*.
    """
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xEDB88320
        else:
            crc >>= 1
    return crc


_crctable: list[int] = list(map(_gen_crc, range(256)))


class _ZipCryptoState:
    """Shared ZipCrypto key schedule used by encryption and decryption."""

    def __init__(self, password: bytes) -> None:
        self.key0: int = 305419896
        self.key1: int = 591751049
        self.key2: int = 878082192
        for value in password:
            self.update_keys(value)

    def crc32(self, value: int, crc: int) -> int:
        return (crc >> 8) ^ _crctable[(crc ^ value) & 0xFF]

    def update_keys(self, value: int) -> None:
        self.key0 = self.crc32(value, self.key0)
        self.key1 = (self.key1 + (self.key0 & 0xFF)) & 0xFFFFFFFF
        self.key1 = (self.key1 * 134775813 + 1) & 0xFFFFFFFF
        self.key2 = self.crc32(self.key1 >> 24, self.key2)

    # ``decrypt`` and ``encrypt`` repeat the ``update_keys`` arithmetic inline:
    # the cipher is inherently byte-serial, and keeping the three keys in local
    # variables avoids a method call and several attribute writes per byte.

    def decrypt(self, data: bytes) -> bytes:
        key0, key1, key2 = self.key0, self.key1, self.key2
        table = _crctable
        result = bytearray(len(data))
        for index, value in enumerate(data):
            key = key2 | 2
            value ^= ((key * (key ^ 1)) >> 8) & 0xFF
            key0 = (key0 >> 8) ^ table[(key0 ^ value) & 0xFF]
            key1 = ((key1 + (key0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            key2 = (key2 >> 8) ^ table[(key2 ^ (key1 >> 24)) & 0xFF]
            result[index] = value
        self.key0, self.key1, self.key2 = key0, key1, key2
        return bytes(result)

    def encrypt(self, data: bytes) -> bytes:
        key0, key1, key2 = self.key0, self.key1, self.key2
        table = _crctable
        result = bytearray(len(data))
        for index, value in enumerate(data):
            key = key2 | 2
            result[index] = value ^ (((key * (key ^ 1)) >> 8) & 0xFF)
            key0 = (key0 >> 8) ^ table[(key0 ^ value) & 0xFF]
            key1 = ((key1 + (key0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            key2 = (key2 >> 8) ^ table[(key2 ^ (key1 >> 24)) & 0xFF]
        self.key0, self.key1, self.key2 = key0, key1, key2
        return bytes(result)


class ZipCryptoDecrypter:
    """Decrypter for traditionally ZipCrypto-encrypted ZIP entries.

    Initialises the three-key state from the password, then verifies the
    password against the last byte of the encryption header.  ZipCrypto has
    no authentication trailer, so :meth:`finalize` checks nothing.
    """

    authenticates_ciphertext: bool = False

    def __init__(
        self, pwd: bytes, encryption_header: bytes, check_byte: int, name: str
    ) -> None:
        """Check *pwd* against *encryption_header* and get ready to decrypt.

        Args:
            pwd (bytes): Decryption password as raw bytes.
            encryption_header (bytes): The 12-byte encryption header read
                from the beginning of the entry data.
            check_byte (int): The value the header's last byte decrypts to
                under the right password.
            name (str): The entry's name, for error messages.

        Raises:
            BadPassword: If *pwd* does not decrypt the header to *check_byte*.
        """
        if len(encryption_header) != ZIP_CRYPTO_HEADER_LENGTH:
            raise BadZipFile("Truncated ZipCrypto encryption header")
        self._state: _ZipCryptoState = _ZipCryptoState(pwd)
        # The first 11 header bytes are random; the 12th is the check byte.
        if self.decrypt(encryption_header)[11] != check_byte:
            raise BadPassword(f"Bad password for file {name!r}")

    def finalize(self, fileobj: object) -> None:
        """Nothing to verify: ZipCrypto has no authentication trailer."""
        del fileobj

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt a chunk of ciphertext.

        Args:
            data (bytes): Ciphertext bytes to decrypt.

        Returns:
            bytes: Decrypted plaintext of the same length as *data*.
        """
        return self._state.decrypt(data)


class ZipCryptoEncryptor:
    """Encryptor for ZipCrypto ZIP entries.

    Initialises the three-key state from the password and produces an
    11-byte random header followed by the check byte.
    """

    def __init__(self, pwd: bytes, check_byte: int) -> None:
        """Initialise the encryptor with a password.

        Args:
            pwd (bytes): Encryption password as raw bytes.
            check_byte (int): The last byte of the plaintext header, which a
                reader checks the password against.

        Raises:
            ValueError: If *pwd* is empty.
        """
        if not pwd:
            raise ValueError(f"{ZIP_CRYPTO} encryption requires a non-empty password")
        self._state: _ZipCryptoState = _ZipCryptoState(pwd)
        self._check_byte: int = check_byte

    def encryption_header(self) -> bytes:
        """Build the 12-byte encrypted header: 11 random bytes and the check byte."""
        return self.encrypt(os.urandom(11) + bytes([self._check_byte]))

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt a chunk of plaintext.

        Args:
            data (bytes): Plaintext bytes to encrypt.

        Returns:
            bytes: Ciphertext of the same length as *data*.
        """
        return self._state.encrypt(data)

    def flush(self) -> bytes:
        """Finalise encryption.

        ZipCrypto has no trailing authentication tag.

        Returns:
            bytes: Always ``b""``.
        """
        return b""
