"""How a provider refusing PBKDF2 is reported."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm

import zipctl
from zipctl.cryptography import aes


class _Refusing:
    error: Exception = UnsupportedAlgorithm("refused")

    def __init__(self, **_kwargs: object) -> None:
        pass

    def derive(self, _pwd: bytes) -> bytes:
        raise self.error


def test_a_refused_short_salt_names_the_fips_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(aes, "PBKDF2HMAC", _Refusing)
    with pytest.raises(NotImplementedError, match="FIPS"):
        aes._derive_key(b"pw", bytes(8), 34)


def test_unrelated_errors_propagate_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_Refusing, "error", MemoryError())
    monkeypatch.setattr(aes, "PBKDF2HMAC", _Refusing)
    with pytest.raises(MemoryError):
        aes._derive_key(b"pw", bytes(8), 34)


def test_extraction_reports_a_refused_member_as_failed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive = tmp_path / "aes128.zip"
    extra = zipctl.ZipFileExtra(wz_aes_nbits=128)
    with zipctl.ZipFile(archive, "w", encryption=zipctl.WZ_AES, extra=extra) as zf:
        zf.setpassword(b"pw")
        zf.writestr("a.txt", b"alpha")
    monkeypatch.setattr(aes, "PBKDF2HMAC", _Refusing)
    with zipctl.ZipFile(archive) as zf, pytest.raises(zipctl.ExtractionError) as raised:
        zf.safe_extractall(tmp_path / "out", pwd=b"pw")
    (member,) = raised.value.result.members
    assert member.status == zipctl.MemberStatus.FAILED
    assert "FIPS" in member.violations[0].message
