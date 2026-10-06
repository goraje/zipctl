"""WZ-AES (AES-CTR + HMAC-SHA1) encryption and decryption for ZIP archives.

Implements the WinZip AES encryption specification using PBKDF2 key derivation,
AES in CTR mode with a little-endian counter, and HMAC-SHA1 authentication.
"""

from __future__ import annotations

import hmac as stdlib_hmac
import os
import sys
import threading
from array import array
from collections import OrderedDict
from typing import Protocol

from cryptography.exceptions import InternalError, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from zipctl.exceptions import BadPassword, BadZipFile
from zipctl.format import read_exactly

__all__ = [
    "WZ_AES",
    "WZ_AES_V1",
    "WZ_AES_V2",
    "EXTRA_WZ_AES",
    "WZ_AES_VENDOR_ID",
    "AES_STRENGTH_BITS",
    "WZ_AES_DEFAULT_VERSION",
    "wz_aes_stores_crc",
    "aes_header_length",
    "AesKeyCache",
    "AesZipDecrypter",
    "AesZipEncryptor",
]

WZ_AES = "WZ_AES"
WZ_AES_COMPRESS_TYPE = 99
WZ_AES_V1 = 0x0001
WZ_AES_V2 = 0x0002
# The version written when none is asked for.
WZ_AES_DEFAULT_VERSION = WZ_AES_V2

EXTRA_WZ_AES = 0x9901

WZ_AES_VENDOR_ID = b"AE"

_WZ_SALT_LENGTHS: dict[int, int] = {
    1: 8,  # 128-bit key
    2: 12,  # 192-bit key
    3: 16,  # 256-bit key
}
_WZ_KEY_LENGTHS: dict[int, int] = {
    1: 16,  # 128-bit key
    2: 24,  # 192-bit key
    3: 32,  # 256-bit key
}

_PWD_VERIFY_LENGTH = 2
# The strength code stored in an archive -> the key size in bits.
AES_STRENGTH_BITS: dict[int, int] = {1: 128, 2: 192, 3: 256}
_NBITS_TO_STRENGTH: dict[int, int] = {
    bits: code for code, bits in AES_STRENGTH_BITS.items()
}


def _derive_key(pwd: bytes, salt: bytes, length: int) -> bytes:
    """WinZip AES key material: PBKDF2-HMAC-SHA1, 1000 iterations."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=length, salt=salt, iterations=1000)
    try:
        return kdf.derive(pwd)
    except (UnsupportedAlgorithm, InternalError) as exc:
        if len(salt) >= 16:
            raise
        # A FIPS provider wants a salt of at least 128 bits: only AES-256 has one.
        raise NotImplementedError(
            f"the cryptography provider refused PBKDF2 with a {len(salt) * 8}-bit "
            "salt (a FIPS provider needs AES-256)"
        ) from exc


def aes_header_length(strength: int) -> int:
    """The salt plus password-verifier length in front of an AES entry's data."""
    return _WZ_SALT_LENGTHS[strength] + _PWD_VERIFY_LENGTH


def wz_aes_stores_crc(version: int | None) -> bool:
    """Whether a WZ-AES entry of *version* (``None``: the default) keeps its CRC-32.

    Version 2 stores 0 in its place and relies on the HMAC alone.
    """
    return (WZ_AES_DEFAULT_VERSION if version is None else version) != WZ_AES_V2


_BLOCK_SIZE = 16


class AesKeyCache:
    """Derived WZ-AES key material, so one password is derived once per member.

    PBKDF2 is the cost of opening an encrypted member (about 1 ms); checking a
    password and then reading the member, or seeking backwards in it, would
    otherwise derive it again.  Only material whose password verifier matched
    is stored, so wrong guesses neither fill the cache nor stay in memory.  The
    cache holds at most *maxsize* entries (least recently used out) and is
    thread-safe.  Keys contain the password, so an owner should :meth:`clear`
    it when done, as :class:`~zipctl.zipfile.file.ZipFile` does on close.
    """

    def __init__(self, maxsize: int = 128) -> None:
        if maxsize < 0:
            raise ValueError("maxsize must be non-negative")
        self._maxsize: int = maxsize
        self._entries: OrderedDict[tuple[bytes, bytes, int], bytes] = OrderedDict()
        self._lock: threading.Lock = threading.Lock()

    def get(self, pwd: bytes, salt: bytes, length: int) -> bytes | None:
        """The key material derived for these inputs, if it is cached."""
        with self._lock:
            material = self._entries.get((pwd, salt, length))
            if material is not None:
                self._entries.move_to_end((pwd, salt, length))
            return material

    def put(self, pwd: bytes, salt: bytes, length: int, material: bytes) -> None:
        """Remember *material* (already checked against its verifier)."""
        with self._lock:
            self._entries[(pwd, salt, length)] = material
            self._entries.move_to_end((pwd, salt, length))
            while len(self._entries) > self._maxsize:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        """Forget everything."""
        with self._lock:
            self._entries.clear()


def _counter_blocks(start: int, count: int) -> bytes:
    """Return *count* consecutive 128-bit little-endian counter blocks.

    Block ``i`` is the integer ``start + i`` in little-endian byte order. The
    counter never approaches 2**64 (that would be 256 EiB of data), so each
    block is a 64-bit word followed by a zero word.
    """
    words = array("Q", bytes(_BLOCK_SIZE * count))
    words[0::2] = array("Q", range(start, start + count))
    if sys.byteorder == "big":  # pragma: no cover - little-endian CI hosts
        words.byteswap()
    return words.tobytes()


def _xor(data: bytes, keystream: bytes) -> bytes:
    """XOR two equal-length byte strings using C-speed big-integer arithmetic."""
    return (
        int.from_bytes(data, "little") ^ int.from_bytes(keystream, "little")
    ).to_bytes(len(data), "little")


class _AesCtrWithLittleEndian:
    """AES-CTR cipher with the little-endian counter WinZip AES specifies.

    Standard CTR implementations (including OpenSSL's) increment the counter
    block as a big-endian integer, so the keystream is built here from raw
    AES block encryptions of little-endian counter blocks.  AES itself stays
    in the ``cryptography`` backend, so a FIPS-configured OpenSSL provider
    still performs every AES operation.

    Whole chunks are processed with one AES call and one big-integer XOR, so
    the Python-level cost is per chunk rather than per block or per byte.

    Attributes:
        counter (int): Next counter value to encrypt (starts at 1).
        keystream_buffer (bytes): Unused bytes left over from the last block.
    """

    def __init__(self, key: bytes) -> None:
        """Initialise the cipher with an AES key.

        Args:
            key (bytes): AES encryption key. Must be 16, 24, or 32 bytes
                (128, 192, or 256 bits).
        """
        self.counter: int = 1
        self.keystream_buffer: bytes = b""
        self._encryptor: CipherContext = Cipher(
            algorithms.AES(key), modes.ECB()
        ).encryptor()

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-CTR with a little-endian counter.

        Args:
            data (bytes): Plaintext bytes to encrypt.

        Returns:
            bytes: Ciphertext of the same length as *data*.
        """
        size = len(data)
        if not size:
            return b""
        keystream = self.keystream_buffer
        missing = size - len(keystream)
        if missing > 0:
            blocks = -(-missing // _BLOCK_SIZE)
            keystream += self._encryptor.update(_counter_blocks(self.counter, blocks))
            self.counter += blocks
        self.keystream_buffer = keystream[size:]
        return _xor(data, keystream[:size])

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using AES-CTR (identical to encryption in CTR mode).

        Args:
            data (bytes): Ciphertext bytes to decrypt.

        Returns:
            bytes: Plaintext of the same length as *data*.
        """
        return self.encrypt(data)


class _Readable(Protocol):
    def read(self, n: int = -1, /) -> bytes: ...


class AesZipDecrypter:
    """Decrypter for WZ-AES encrypted ZIP entries.

    Derives the AES and HMAC keys from a password and salt using PBKDF2,
    then decrypts entry data with AES-CTR and verifies integrity with
    HMAC-SHA1.

    Attributes:
        hmac_size (int): Number of bytes of the HMAC digest appended to
            the ciphertext (always 10).
        authenticates_ciphertext (bool): Always ``True``: the HMAC proves the
            entry intact without decompressing it.
    """

    hmac_size: int = 10
    authenticates_ciphertext: bool = True

    def __init__(
        self,
        pwd: bytes,
        encryption_header: bytes,
        strength: int,
        name: str,
        key_cache: AesKeyCache | None = None,
    ) -> None:
        """Check *pwd* against *encryption_header* and get ready to decrypt.

        Args:
            pwd (bytes): Decryption password.
            encryption_header (bytes): Salt and password-verification bytes
                read from the beginning of the entry data.
            strength (int): The WZ-AES strength code (1, 2 or 3).
            name (str): The entry's name, for error messages.
            key_cache (AesKeyCache | None): Where to look for, and keep, the
                derived keys.  ``None`` derives them every time.

        Raises:
            BadZipFile: If *encryption_header* is not as long as *strength* needs.
            BadPassword: If *pwd* does not match the password-verification
                bytes in *encryption_header*.
        """
        self.filename: str = name
        key_length = _WZ_KEY_LENGTHS[strength]
        salt_length = _WZ_SALT_LENGTHS[strength]
        if len(encryption_header) != salt_length + _PWD_VERIFY_LENGTH:
            raise BadZipFile("Truncated AES encryption header")

        salt = encryption_header[:salt_length]
        pwd_verify = encryption_header[salt_length : salt_length + _PWD_VERIFY_LENGTH]
        dk_len = 2 * key_length + _PWD_VERIFY_LENGTH

        keymaterial = (
            key_cache.get(pwd, salt, dk_len) if key_cache is not None else None
        )
        if keymaterial is None:
            keymaterial = _derive_key(pwd, salt, dk_len)

        # Also for cached material: a header may carry a verifier of its own.
        if not stdlib_hmac.compare_digest(keymaterial[2 * key_length :], pwd_verify):
            raise BadPassword(f"Bad password for file {name!r}")
        if key_cache is not None:
            key_cache.put(pwd, salt, dk_len, keymaterial)

        self.decrypter: _AesCtrWithLittleEndian = _AesCtrWithLittleEndian(
            keymaterial[:key_length]
        )
        self.hmac: hmac.HMAC = hmac.HMAC(
            keymaterial[key_length : 2 * key_length],
            hashes.SHA1(),
        )

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt a chunk of ciphertext and update the running HMAC.

        Args:
            data (bytes): Ciphertext bytes to decrypt.

        Returns:
            bytes: Decrypted plaintext of the same length as *data*.
        """
        self.hmac.update(data)
        return self.decrypter.decrypt(data)

    def check_hmac(self, hmac_check: bytes) -> None:
        """Verify the HMAC-SHA1 authentication tag for the decrypted entry.

        Args:
            hmac_check (bytes): The 10-byte HMAC digest appended to the
                ciphertext.

        Raises:
            BadZipFile: If the computed HMAC does not match *hmac_check*.
        """
        if len(hmac_check) != self.hmac_size:
            raise BadZipFile(f"Truncated HMAC check for file {self.filename!r}")
        hmac_copy = self.hmac.copy()
        if not stdlib_hmac.compare_digest(
            hmac_copy.finalize()[: self.hmac_size], hmac_check
        ):
            raise BadZipFile(f"Bad HMAC check for file {self.filename!r}")

    def finalize(self, fileobj: _Readable) -> None:
        """Read the HMAC tag that follows the ciphertext and verify it."""
        try:
            hmac_check = read_exactly(fileobj, self.hmac_size)
        except EOFError as exc:
            raise BadZipFile(
                f"Truncated HMAC check for file {self.filename!r}"
            ) from exc
        self.check_hmac(hmac_check)


class AesZipEncryptor:
    """Encryptor for WZ-AES ZIP entries.

    Generates a random salt, derives AES and HMAC keys from the password
    using PBKDF2, encrypts entry data with AES-CTR, and produces a
    10-byte HMAC-SHA1 authentication tag.

    Attributes:
        hmac_size (int): Number of HMAC bytes appended after the ciphertext
            (always 10).
        strength (int): WZ-AES strength code (1=128-bit, 2=192-bit, 3=256-bit).
        salt (bytes): Randomly generated salt used for key derivation.
        encpwdverify (bytes): Password-verification bytes included in the
            encryption header.
    """

    hmac_size: int = 10

    def __init__(self, pwd: bytes, nbits: int = 256) -> None:
        """Initialise the encryptor with a password and key size.

        Args:
            pwd (bytes): Encryption password.
            nbits (int): AES key size in bits. Must be 128, 192, or 256.
                Defaults to 256.

        Raises:
            ValueError: If *pwd* is empty or *nbits* is not 128, 192 or 256.
        """
        if not pwd:
            raise ValueError(f"{WZ_AES} encryption requires a non-empty password")
        if nbits not in (128, 192, 256):
            raise ValueError(f"nbits must be 128, 192 or 256, not {nbits!r}")

        self.strength: int = _NBITS_TO_STRENGTH[nbits]
        key_length = _WZ_KEY_LENGTHS[self.strength]

        self.salt: bytes = os.urandom(_WZ_SALT_LENGTHS[self.strength])
        dk_len = 2 * key_length + _PWD_VERIFY_LENGTH

        keymaterial = _derive_key(pwd, self.salt, dk_len)

        self.encpwdverify: bytes = keymaterial[2 * key_length :]
        self.encryptor: _AesCtrWithLittleEndian = _AesCtrWithLittleEndian(
            keymaterial[:key_length]
        )
        self.hmac: hmac.HMAC = hmac.HMAC(
            keymaterial[key_length : 2 * key_length],
            hashes.SHA1(),
        )

    def encryption_header(self) -> bytes:
        """Build the encryption header to prepend to the ciphertext.

        Returns:
            bytes: Concatenation of the random salt and the
            password-verification bytes.
        """
        return self.salt + self.encpwdverify

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt a chunk of plaintext and update the running HMAC.

        Args:
            data (bytes): Plaintext bytes to encrypt.

        Returns:
            bytes: Ciphertext of the same length as *data*.
        """
        data = self.encryptor.encrypt(data)
        self.hmac.update(data)
        return data

    def flush(self) -> bytes:
        """Finalise encryption and return the HMAC authentication tag.

        Returns:
            bytes: First :attr:`hmac_size` (10) bytes of the HMAC-SHA1
            digest, to be appended after the ciphertext.
        """
        return self.hmac.copy().finalize()[: self.hmac_size]
