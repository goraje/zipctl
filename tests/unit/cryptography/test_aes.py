from __future__ import annotations

import io
import os

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from zipctl.cryptography.aes import (
    AesZipDecrypter,
    AesZipEncryptor,
    _AesCtrWithLittleEndian,
    _counter_blocks,
    aes_header_length,
)
from zipctl.exceptions import BadZipFile

# ---------------------------------------------------------------------------
# AesZipEncryptor
# ---------------------------------------------------------------------------


class TestAesZipEncryptor:
    @pytest.mark.parametrize(
        ("nbits", "expected_strength", "expected_salt_len"),
        [
            (128, 1, 8),
            (192, 2, 12),
            (256, 3, 16),
        ],
    )
    def test_strength_and_salt_length_per_nbits(
        self, nbits: int, expected_strength: int, expected_salt_len: int
    ) -> None:
        enc = AesZipEncryptor(b"password", nbits=nbits)
        assert enc.strength == expected_strength
        assert len(enc.salt) == expected_salt_len
        assert len(enc.encryption_header()) == aes_header_length(enc.strength)

    def test_empty_password_raises(self) -> None:
        with pytest.raises(ValueError, match="requires a non-empty password"):
            AesZipEncryptor(b"")

    @pytest.mark.parametrize("nbits", [64, 512])
    def test_invalid_nbits_raises(self, nbits: int) -> None:
        with pytest.raises(ValueError, match="nbits"):
            AesZipEncryptor(b"pass", nbits=nbits)

    def test_flush_returns_ten_bytes(self) -> None:
        enc = AesZipEncryptor(b"pass")
        enc.encrypt(b"some data")
        result = enc.flush()
        assert isinstance(result, bytes)
        assert len(result) == 10

    def test_encryption_header_is_salt_plus_verify(self) -> None:
        enc = AesZipEncryptor(b"pass", nbits=256)
        header = enc.encryption_header()
        assert header == enc.salt + enc.encpwdverify
        assert len(header) == 18  # 16 (salt) + 2 (verify)

    def test_different_instances_have_different_salts(self) -> None:
        enc1 = AesZipEncryptor(b"pass")
        enc2 = AesZipEncryptor(b"pass")
        # Two random 16-byte values will differ with overwhelming probability
        assert enc1.salt != enc2.salt


# ---------------------------------------------------------------------------
# AesZipDecrypter
# ---------------------------------------------------------------------------


def _decrypter(enc: AesZipEncryptor, pwd: bytes, header: bytes) -> AesZipDecrypter:
    return AesZipDecrypter(pwd, header, enc.strength, "f")


class TestAesZipDecrypter:
    def test_wrong_password_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # a fixed salt: with a random one, 1 in 65536 wrong passwords pass the check
        monkeypatch.setattr(os, "urandom", bytes)  # n zero bytes
        enc = AesZipEncryptor(b"correct")
        with pytest.raises(RuntimeError, match="Bad password for file 'f'"):
            _decrypter(enc, b"wrong", enc.encryption_header())

    @pytest.mark.parametrize(("strength", "length"), [(1, 10), (2, 14), (3, 18)])
    def test_encryption_header_length(self, strength: int, length: int) -> None:
        assert aes_header_length(strength) == length

    def test_decrypt_round_trip(self) -> None:
        plaintext = b"the quick brown fox jumps over the lazy dog"
        enc = AesZipEncryptor(b"hunter2")
        header = enc.encryption_header()
        ciphertext = enc.encrypt(plaintext)
        dec = _decrypter(enc, b"hunter2", header)
        assert dec.decrypt(ciphertext) == plaintext
        assert dec.authenticates_ciphertext

    def test_finalize_accepts_the_tag(self) -> None:
        enc = AesZipEncryptor(b"pw")
        dec = _decrypter(enc, b"pw", enc.encryption_header())
        dec.decrypt(enc.encrypt(b"sample data"))
        dec.finalize(io.BytesIO(enc.flush()))  # must not raise

    def test_finalize_refuses_a_wrong_tag(self) -> None:
        enc = AesZipEncryptor(b"pw")
        dec = _decrypter(enc, b"pw", enc.encryption_header())
        dec.decrypt(enc.encrypt(b"data"))
        with pytest.raises(BadZipFile, match="Bad HMAC check for file 'f'"):
            dec.finalize(io.BytesIO(b"\x00" * 10))

    def test_check_hmac_raises_for_truncated_tag(self) -> None:
        enc = AesZipEncryptor(b"pw")
        dec = _decrypter(enc, b"pw", enc.encryption_header())
        dec.decrypt(enc.encrypt(b"data"))
        with pytest.raises(BadZipFile, match="Truncated HMAC"):
            dec.check_hmac(enc.flush()[:-1])

    def test_an_hmac_cut_off_at_the_end_of_the_entry_is_refused(self) -> None:
        enc = AesZipEncryptor(b"pw")
        dec = _decrypter(enc, b"pw", enc.encryption_header())
        dec.decrypt(enc.encrypt(b"data"))
        with pytest.raises(BadZipFile, match="Truncated HMAC check"):
            dec.finalize(io.BytesIO(enc.flush()[:-1]))

    def test_a_short_salt_header_is_refused(self) -> None:
        enc = AesZipEncryptor(b"pw")
        with pytest.raises(BadZipFile, match="Truncated AES encryption header"):
            _decrypter(enc, b"pw", enc.encryption_header()[:-1])


# ---------------------------------------------------------------------------
# WinZip little-endian CTR: known answers and reference equivalence
# ---------------------------------------------------------------------------

_KAT_PLAINTEXT = bytes((i * 7 + 3) & 0xFF for i in range(100))
# Generated from the original per-block implementation (WinZip-compatible).
_KAT_CIPHERTEXT = {
    16: "e076c27bc25aaa94a1bd476e37bef9ee88f062932a4d01093c84f447e51aa6fa6f5268ec7019a5eb8a10f9db229773bea3d6ec6cfc649743e41d39f0dfb93f1dbb5716b414b423e8c6bb07db2264d322d804a91909475a9aa900ee32fd5b70ffa9fe725e",  # noqa: E501
    24: "0a406324f5d1da8309a212c08405e99ddb87d0e5739f561d18393ce738eb6e3810bf482440e719cb4bee03101ed3f51f8b8be750c43197df9180ca6c2cefe3cd8ed9f46c4949994db29c6bd8d0c9e8342a303539c1e6347d89bab720c101e099776fd231",  # noqa: E501
    32: "c4bf089c75376c28edee4e9b54a664c43d8e39036443d4f768cd4336a9341fa76329f086708fa62545fc1b812976ee1c862208685c3dc729ba3af16a9b8797a75a211d18ce9fa4399d3e4dd07d027d9c6e90965b60d6c559c5fa957949ffdf87c3aea01c",  # noqa: E501
}


def _reference_ctr(key: bytes, data: bytes) -> bytes:
    """Straightforward WinZip CTR: one AES block per little-endian counter."""
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray()
    for block, offset in enumerate(range(0, len(data), 16), start=1):
        keystream = encryptor.update(block.to_bytes(16, "little"))
        chunk = data[offset : offset + 16]
        out.extend(a ^ b for a, b in zip(chunk, keystream, strict=False))
    return bytes(out)


@pytest.mark.parametrize("key_length", [16, 24, 32])
def test_known_answer_split_across_calls(key_length: int) -> None:
    cipher = _AesCtrWithLittleEndian(bytes(range(key_length)))
    ciphertext = cipher.encrypt(_KAT_PLAINTEXT[:37]) + cipher.encrypt(
        _KAT_PLAINTEXT[37:]
    )
    assert ciphertext.hex() == _KAT_CIPHERTEXT[key_length]


@pytest.mark.parametrize(
    "sizes",
    [
        [0],
        [1],
        [15, 1],
        [16],
        [17, 15],
        [1] * 40,
        [3, 0, 29, 16, 1, 100],
        [65536 + 5, 7],
    ],
)
def test_chunking_never_changes_the_stream(sizes: list[int]) -> None:
    key = os.urandom(32)
    data = os.urandom(sum(sizes))
    cipher = _AesCtrWithLittleEndian(key)
    produced = bytearray()
    offset = 0
    for size in sizes:
        produced += cipher.encrypt(data[offset : offset + size])
        offset += size
    assert bytes(produced) == _reference_ctr(key, data)


def test_counter_blocks_are_little_endian() -> None:
    blocks = _counter_blocks(255, 3)
    assert blocks[0:16] == (255).to_bytes(16, "little")
    assert blocks[16:32] == (256).to_bytes(16, "little")
    assert blocks[32:48] == (257).to_bytes(16, "little")
