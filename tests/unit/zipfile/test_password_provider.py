from __future__ import annotations

import io
from collections.abc import Mapping
from pathlib import Path

import pytest

import zipctl
from zipctl import (
    BadPassword,
    ExtractPolicy,
    MemberStatus,
    PasswordRequired,
    ZipFile,
)
from zipctl.zipfile.info import ZipInfo

PASSWORDS = {"alpha.txt": b"pass-alpha", "beta.txt": b"pass-beta"}


@pytest.fixture
def archive() -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", encryption=zipctl.WZ_AES) as zf:
        zf.writestr("alpha.txt", b"alpha data", password=PASSWORDS["alpha.txt"])
        zf.writestr("beta.txt", b"beta data", password=PASSWORDS["beta.txt"])
        zf.writestr("plain.txt", b"plain data", encryption=None)
    return buffer.getvalue()


class Provider:
    """Hands out the right password per member and records what it was asked."""

    def __init__(self, table: dict[str, bytes | None] | None = None) -> None:
        self.table: Mapping[str, bytes | None] = PASSWORDS if table is None else table
        self.asked: list[str] = []

    def __call__(self, info: ZipInfo) -> bytes | None:
        self.asked.append(info.filename)
        return self.table.get(info.filename)


def test_extractall_gives_every_encrypted_member_its_own_password(
    archive: bytes, tmp_path: Path
) -> None:
    provider = Provider()
    with ZipFile(io.BytesIO(archive)) as zf:
        zf.extractall(tmp_path, pwd=provider)
    assert (tmp_path / "alpha.txt").read_bytes() == b"alpha data"
    assert (tmp_path / "beta.txt").read_bytes() == b"beta data"
    assert (tmp_path / "plain.txt").read_bytes() == b"plain data"


def test_the_provider_is_only_asked_about_encrypted_members(
    archive: bytes, tmp_path: Path
) -> None:
    provider = Provider()
    with ZipFile(io.BytesIO(archive)) as zf:
        zf.extractall(tmp_path, pwd=provider)
    assert provider.asked == ["alpha.txt", "beta.txt"]


def test_extract_a_single_member_with_a_provider(
    archive: bytes, tmp_path: Path
) -> None:
    provider = Provider()
    with ZipFile(io.BytesIO(archive)) as zf:
        zf.extract("beta.txt", tmp_path, pwd=provider)
    assert provider.asked == ["beta.txt"]
    assert (tmp_path / "beta.txt").read_bytes() == b"beta data"


def test_policy_extraction_uses_the_provider(archive: bytes, tmp_path: Path) -> None:
    provider = Provider()
    with ZipFile(io.BytesIO(archive)) as zf:
        result = zf.extractall(tmp_path, pwd=provider, policy=ExtractPolicy())
    assert result.extracted_count == 3
    assert provider.asked == ["alpha.txt", "beta.txt"]


def test_provider_works_together_with_progress_callbacks(
    archive: bytes, tmp_path: Path
) -> None:
    events: list[zipctl.ProgressEvent] = []
    with ZipFile(io.BytesIO(archive)) as zf:
        zf.extractall(tmp_path, pwd=Provider(), progress=events.append)
    finished = [e.member for e in events if e.phase == zipctl.ProgressPhase.FINISH]
    assert finished == ["alpha.txt", "beta.txt", "plain.txt"]


def test_a_missing_password_fails_plain_extraction_with_password_required(
    archive: bytes, tmp_path: Path
) -> None:
    provider = Provider({"alpha.txt": PASSWORDS["alpha.txt"]})  # beta unknown
    with ZipFile(io.BytesIO(archive)) as zf:
        with pytest.raises(PasswordRequired):
            zf.extractall(tmp_path, pwd=provider)
    assert (tmp_path / "alpha.txt").exists()
    assert not (tmp_path / "beta.txt").exists()


def test_a_missing_password_fails_only_that_member_under_a_policy(
    archive: bytes, tmp_path: Path
) -> None:
    provider = Provider({"alpha.txt": PASSWORDS["alpha.txt"]})
    with ZipFile(io.BytesIO(archive)) as zf:
        with pytest.raises(zipctl.ExtractionError) as excinfo:
            zf.extractall(tmp_path, pwd=provider, policy=ExtractPolicy())
    statuses = {m.member: m.status for m in excinfo.value.result.members}
    assert statuses == {
        "alpha.txt": MemberStatus.EXTRACTED,
        "beta.txt": MemberStatus.FAILED,
        "plain.txt": MemberStatus.EXTRACTED,
    }
    assert not (tmp_path / "beta.txt").exists()


def test_a_wrong_password_is_reported_as_wrong(archive: bytes, tmp_path: Path) -> None:
    provider = Provider({"alpha.txt": b"nope", "beta.txt": PASSWORDS["beta.txt"]})
    with ZipFile(io.BytesIO(archive)) as zf:
        with pytest.raises(BadPassword):
            zf.extractall(tmp_path, pwd=provider)


def test_a_provider_can_raise_its_own_password_error(
    archive: bytes, tmp_path: Path
) -> None:
    def provider(info: ZipInfo) -> bytes | None:
        raise BadPassword(f"no key for {info.filename}")

    with ZipFile(io.BytesIO(archive)) as zf:
        with pytest.raises(zipctl.ExtractionError) as excinfo:
            zf.extractall(tmp_path, pwd=provider, policy=ExtractPolicy())
    messages = {
        m.member: m.violations[0].message
        for m in excinfo.value.result.members
        if m.status == MemberStatus.FAILED
    }
    assert messages == {
        "alpha.txt": "no key for alpha.txt",
        "beta.txt": "no key for beta.txt",
    }


def test_a_provider_returning_the_wrong_type_is_rejected(
    archive: bytes, tmp_path: Path
) -> None:
    with ZipFile(io.BytesIO(archive)) as zf:
        with pytest.raises(TypeError, match="expected bytes"):
            zf.extractall(tmp_path, pwd=lambda info: "text")  # type: ignore[arg-type,return-value]  # ty: ignore[invalid-argument-type]  # pyright: ignore[reportArgumentType]


def test_plain_bytes_passwords_and_the_archive_password_still_work(
    tmp_path: Path,
) -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", encryption=zipctl.WZ_AES) as zf:
        zf.setpassword(b"shared")
        zf.writestr("a.txt", b"a")
        zf.writestr("b.txt", b"b")
    with ZipFile(io.BytesIO(buffer.getvalue())) as zf:
        zf.extractall(tmp_path / "explicit", pwd=b"shared")
        zf.setpassword(b"shared")
        zf.extractall(tmp_path / "default")
    assert (tmp_path / "explicit" / "b.txt").read_bytes() == b"b"
    assert (tmp_path / "default" / "a.txt").read_bytes() == b"a"
