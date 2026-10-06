from __future__ import annotations

import io
import os
import struct
from typing import cast

import pytest

import zipctl
from tests.helpers import NonSeekableBytesIO
from zipctl import (
    BadPassword,
    PasswordCheckResult,
    PasswordError,
    PasswordRequired,
    PasswordStatus,
    ZipFileExtra,
)
from zipctl.zipfile.file.ext import ZipExtFile

PASSWORD = b"correct horse"
PAYLOAD = b"secret payload " * 40


CASES = {
    "aes128-v2": (zipctl.WZ_AES, ZipFileExtra(wz_aes_nbits=128), True),
    "aes192-v2": (zipctl.WZ_AES, ZipFileExtra(wz_aes_nbits=192), True),
    "aes256-v2": (zipctl.WZ_AES, ZipFileExtra(wz_aes_nbits=256), True),
    "aes256-v1": (zipctl.WZ_AES, ZipFileExtra(force_wz_aes_version=1), True),
    "zipcrypto-crc": (zipctl.ZIP_CRYPTO, None, True),
    "zipcrypto-descriptor": (zipctl.ZIP_CRYPTO, None, False),
}


def _build(case: str, compression: int = zipctl.ZIP_STORED) -> bytes:
    encryption, extra, seekable = CASES[case]
    buffer = io.BytesIO() if seekable else NonSeekableBytesIO()
    with zipctl.ZipFile(
        buffer, "w", compression=compression, encryption=encryption, extra=extra
    ) as zf:
        zf.setpassword(PASSWORD)
        zf.writestr("secret.txt", PAYLOAD)
        zf.writestr("plain.txt", b"not secret", encryption=None)
    return buffer.getvalue()


_AES_SALT_LENGTH = {1: 8, 2: 12, 3: 16}


def _flip_payload_byte(data: bytes, name: str) -> bytes:
    """Corrupt one byte just past the encryption header of *name*."""
    with zipctl.ZipFile(io.BytesIO(data)) as zf:
        info = zf.getinfo(name)
    name_len, extra_len = struct.unpack_from("<HH", data, info.header_offset + 26)
    aes = info.aes_extra
    header_length = 12 if aes is None else _AES_SALT_LENGTH[aes.wz_aes_strength] + 2
    position = info.header_offset + 30 + name_len + extra_len + header_length + 3
    corrupted = bytearray(data)
    corrupted[position] ^= 0xFF
    return bytes(corrupted)


@pytest.fixture(autouse=True)
def _deterministic_salts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fix the random header/salt bytes.

    A wrong password legitimately passes the header check now and then (1 in
    256 for ZipCrypto), so random headers would make the rejection tests flaky.
    """

    def urandom(size: int) -> bytes:
        return bytes(range(size))

    monkeypatch.setattr(os, "urandom", urandom)


@pytest.fixture(params=list(CASES))
def case(request: pytest.FixtureRequest) -> str:
    return cast("str", request.param)


def test_correct_password_is_accepted(case: str) -> None:
    with zipctl.ZipFile(io.BytesIO(_build(case))) as zf:
        result = zf.check_password(PASSWORD)
    assert result.accepted == ("secret.txt",)
    assert result.unencrypted == ("plain.txt",)
    assert result.rejected == ()
    assert result.corrupt == ()
    assert result.ok


def test_wrong_password_is_rejected(case: str) -> None:
    with zipctl.ZipFile(io.BytesIO(_build(case))) as zf:
        result = zf.check_password(b"wrong password")
    assert result.rejected == ("secret.txt",)
    assert result.unencrypted == ("plain.txt",)
    assert not result.ok


def test_defaults_to_archive_password_and_supports_member_subsets() -> None:
    with zipctl.ZipFile(io.BytesIO(_build("aes256-v2"))) as zf:
        zf.setpassword(PASSWORD)
        assert zf.check_password().accepted == ("secret.txt",)
        by_name = zf.check_password(members=["plain.txt"])
        by_info = zf.check_password(members=[zf.getinfo("secret.txt")])
    assert [c.status for c in by_name.members] == [PasswordStatus.UNENCRYPTED]
    assert [c.status for c in by_info.members] == [PasswordStatus.ACCEPTED]


def test_per_entry_passwords_are_checked_one_password_at_a_time() -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w", encryption=zipctl.WZ_AES) as zf:
        zf.writestr("a.txt", b"a", password=b"pw-a")
        zf.writestr("b.txt", b"b", password=b"pw-b")
    with zipctl.ZipFile(io.BytesIO(buffer.getvalue())) as zf:
        first = zf.check_password(b"pw-a")
        second = zf.check_password(b"pw-b")
    assert (first.accepted, first.rejected) == (("a.txt",), ("b.txt",))
    assert (second.accepted, second.rejected) == (("b.txt",), ("a.txt",))


def test_archive_without_encrypted_members_is_ok() -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("plain.txt", b"x")
    with zipctl.ZipFile(io.BytesIO(buffer.getvalue())) as zf:
        result = zf.check_password(b"anything")
    assert result.ok
    assert result.unencrypted == ("plain.txt",)


def test_password_argument_errors() -> None:
    with zipctl.ZipFile(io.BytesIO(_build("aes256-v2"))) as zf:
        with pytest.raises(ValueError, match="non-empty password"):
            zf.check_password()
        with pytest.raises(ValueError, match="non-empty password"):
            zf.check_password(b"")
        with pytest.raises(TypeError, match="expected bytes"):
            zf.check_password("text")  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]  # pyright: ignore[reportArgumentType]
        with pytest.raises(KeyError):
            zf.check_password(PASSWORD, members=["missing.txt"])
    with pytest.raises(ValueError, match="closed"):
        zf.check_password(PASSWORD)


def test_header_check_never_reads_the_payload(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("payload was read")

    monkeypatch.setattr(ZipExtFile, "_read1", forbidden)
    monkeypatch.setattr(ZipExtFile, "_read2", forbidden)
    with zipctl.ZipFile(io.BytesIO(_build(case))) as zf:
        assert zf.check_password(PASSWORD).ok
        assert zf.check_password(b"wrong password").rejected == ("secret.txt",)


def test_full_check_accepts_intact_and_rejects_wrong_password(case: str) -> None:
    with zipctl.ZipFile(io.BytesIO(_build(case))) as zf:
        assert zf.check_password(PASSWORD, full=True).accepted == ("secret.txt",)
        assert zf.check_password(b"wrong password", full=True).rejected == (
            "secret.txt",
        )


def test_full_check_reports_corrupt_data(case: str) -> None:
    data = _flip_payload_byte(_build(case), "secret.txt")
    with zipctl.ZipFile(io.BytesIO(data)) as zf:
        header_only = zf.check_password(PASSWORD)
        full = zf.check_password(PASSWORD, full=True)
    assert header_only.accepted == ("secret.txt",)
    assert full.corrupt == ("secret.txt",)
    assert not full.ok


def test_aes_full_check_authenticates_without_decompressing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _build("aes256-v2", compression=zipctl.ZIP_DEFLATED)

    def forbidden(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("payload was decompressed")

    monkeypatch.setattr(ZipExtFile, "_read1", forbidden)
    with zipctl.ZipFile(io.BytesIO(data)) as zf:
        assert zf.check_password(PASSWORD, full=True).ok
    corrupt = _flip_payload_byte(data, "secret.txt")
    with zipctl.ZipFile(io.BytesIO(corrupt)) as zf:
        assert zf.check_password(PASSWORD, full=True).corrupt == ("secret.txt",)


def test_check_password_refused_while_writing() -> None:
    with zipctl.ZipFile(io.BytesIO(), "w") as zf:
        writer = zf.open("a.txt", "w")
        try:
            with pytest.raises(ValueError, match="open writing handle"):
                zf.check_password(PASSWORD)
        finally:
            writer.close()


def test_password_exceptions_are_runtime_errors() -> None:
    assert issubclass(BadPassword, PasswordError)
    assert issubclass(PasswordRequired, PasswordError)
    assert issubclass(PasswordError, RuntimeError)


def test_open_raises_typed_password_errors(case: str) -> None:
    with zipctl.ZipFile(io.BytesIO(_build(case))) as zf:
        with pytest.raises(PasswordRequired):
            zf.read("secret.txt")
        with pytest.raises(BadPassword):
            zf.read("secret.txt", pwd=b"wrong password")
        assert zf.read("secret.txt", pwd=PASSWORD) == PAYLOAD


def test_result_properties_group_members_by_status() -> None:
    result = PasswordCheckResult(
        (
            zipctl.MemberPasswordCheck("a", PasswordStatus.ACCEPTED),
            zipctl.MemberPasswordCheck("b", PasswordStatus.REJECTED),
            zipctl.MemberPasswordCheck("c", PasswordStatus.CORRUPT),
            zipctl.MemberPasswordCheck("d", PasswordStatus.UNENCRYPTED),
        )
    )
    assert (result.accepted, result.rejected) == (("a",), ("b",))
    assert (result.corrupt, result.unencrypted) == (("c",), ("d",))
    assert not result.ok
