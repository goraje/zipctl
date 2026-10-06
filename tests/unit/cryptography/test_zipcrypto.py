from __future__ import annotations

import os
import zlib
from unittest.mock import patch

import pytest

from zipctl.cryptography.zipcrypto import (
    ZipCryptoDecrypter,
    ZipCryptoEncryptor,
    _gen_crc,
    _ZipCryptoState,
)
from zipctl.exceptions import BadZipFile

CHECK = 0x5A


def _make_enc_header(
    pwd: bytes, check_byte: int = CHECK
) -> tuple[ZipCryptoEncryptor, bytes]:
    """Return a fresh encryptor and its encryption header."""
    enc = ZipCryptoEncryptor(pwd, check_byte)
    return enc, enc.encryption_header()


# ---------------------------------------------------------------------------
# _gen_crc
# ---------------------------------------------------------------------------


class TestGenCrc:
    def test_the_table_is_the_standard_crc32_table(self) -> None:
        # entry i is the CRC-32 register after byte i, without pre/post inversion
        for i in range(256):
            assert _gen_crc(i) == zlib.crc32(bytes([i]), 0xFFFFFFFF) ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# ZipCryptoEncryptor
# ---------------------------------------------------------------------------


class TestZipCryptoEncryptor:
    def test_empty_password_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty password"):
            ZipCryptoEncryptor(b"", CHECK)

    def test_initial_key_state_with_empty_password(self) -> None:
        state = _ZipCryptoState(b"")
        assert state.key0 == 305419896
        assert state.key1 == 591751049
        assert state.key2 == 878082192

    def test_key_state_for_a_password_is_the_known_answer(self) -> None:
        # derived independently from APPNOTE 6.1.5 with zlib.crc32
        state = ZipCryptoEncryptor(b"password", CHECK)._state
        assert (state.key0, state.key1, state.key2) == (
            3936046669,
            3128463493,
            1610117245,
        )

    def test_the_header_ends_with_the_check_byte(self) -> None:
        _, header = _make_enc_header(b"pw")
        assert len(header) == 12
        assert _ZipCryptoState(b"pw").decrypt(header)[11] == CHECK

    def test_different_calls_produce_different_headers(self) -> None:
        # Headers contain random bytes so two fresh calls should differ
        _, h1 = _make_enc_header(b"pw")
        _, h2 = _make_enc_header(b"pw")
        assert h1 != h2


# ---------------------------------------------------------------------------
# ZipCryptoDecrypter
# ---------------------------------------------------------------------------


class TestZipCryptoDecrypter:
    def test_the_right_password_passes_the_check_byte(self) -> None:
        enc, header = _make_enc_header(b"correct")
        dec = ZipCryptoDecrypter(b"correct", header, CHECK, "f")
        # Decrypter state is in sync with the encryptor only if the check passed.
        assert dec.decrypt(enc.encrypt(b"payload")) == b"payload"
        dec.finalize(None)  # no trailer to check

    def test_wrong_password_raises_runtime_error(self) -> None:
        # Patch os.urandom so the encryption header is deterministic across runs.
        # Without this, h[11] with a wrong password is a random byte and there is
        # a 1/256 chance it accidentally matches the check byte, silently passing.
        with patch(
            "zipctl.cryptography.zipcrypto.os.urandom", return_value=b"\x00" * 11
        ):
            _, header = _make_enc_header(b"correct")
        with pytest.raises(RuntimeError, match="Bad password for file 'f'"):
            ZipCryptoDecrypter(b"wrong", header, CHECK, "f")

    def test_another_check_byte_is_a_wrong_password(self) -> None:
        _, header = _make_enc_header(b"correct")
        with pytest.raises(RuntimeError, match="Bad password"):
            ZipCryptoDecrypter(b"correct", header, CHECK ^ 1, "f")

    def test_a_short_header_is_refused(self) -> None:
        _, header = _make_enc_header(b"pw")
        with pytest.raises(BadZipFile, match="Truncated ZipCrypto encryption header"):
            ZipCryptoDecrypter(b"pw", header[:11], CHECK, "f")

    @pytest.mark.parametrize("plaintext", [b"a", b"x" * 16, b"y" * 100])
    def test_round_trip_various_lengths(self, plaintext: bytes) -> None:
        enc, header = _make_enc_header(b"multitest")
        ciphertext = enc.encrypt(plaintext)
        dec = ZipCryptoDecrypter(b"multitest", header, CHECK, "f")
        assert dec.decrypt(ciphertext) == plaintext


# ---------------------------------------------------------------------------
# Inlined key schedule must match the straightforward per-byte definition
# ---------------------------------------------------------------------------


def _reference_encrypt(pwd: bytes, data: bytes) -> bytes:
    state = _ZipCryptoState(pwd)
    out = bytearray()
    for value in data:
        key = state.key2 | 2
        stream_byte = ((key * (key ^ 1)) >> 8) & 0xFF
        state.update_keys(value)
        out.append(value ^ stream_byte)
    return bytes(out)


def test_encrypt_matches_reference_and_decrypt_inverts_it() -> None:
    data = bytes(range(256)) * 5
    ciphertext = _ZipCryptoState(b"secret").encrypt(data)
    assert ciphertext == _reference_encrypt(b"secret", data)
    assert _ZipCryptoState(b"secret").decrypt(ciphertext) == data


def test_state_carries_over_between_chunks() -> None:
    data = os.urandom(1000)
    whole = _ZipCryptoState(b"pw").encrypt(data)
    chunked = _ZipCryptoState(b"pw")
    assert (
        chunked.encrypt(data[:1])
        + chunked.encrypt(data[1:700])
        + chunked.encrypt(data[700:])
        == whole
    )
