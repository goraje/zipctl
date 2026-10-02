"""Adversarial extraction cases spanning metadata, policies and filesystem writes."""

from __future__ import annotations

import io
import os
import stat
import struct
from pathlib import Path

import pytest

from zipctl import (
    ExtractionError,
    ExtractPolicy,
    OverwritePolicy,
    ViolationAction,
    ZipFile,
)
from zipctl.zipfile.exceptions import ExtractionQuotaExceeded
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.materialize import ExtractionQuota, MaterializationResult
from zipctl.zipfile.policy_extraction import extract_with_policy
from zipctl.zipfile.progress import ProgressReporter
from zipctl.zipfile.shared import crc32


def _archive(info: ZipInfo, data: bytes = b"payload") -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr(info, data)
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("original", "effective"),
    [("payload.exe", "safe.txt"), ("safe.txt", "payload.exe")],
)
def test_unicode_path_and_extension_policy_agree(
    tmp_path: Path, original: str, effective: str
) -> None:
    info = ZipInfo(original)
    extra = struct.pack("<BL", 1, crc32(original.encode())) + effective.encode()
    info.extra = struct.pack("<HH", 0x7075, len(extra)) + extra
    with ZipFile(io.BytesIO(_archive(info))) as archive:
        policy = ExtractPolicy(blocked_extensions=frozenset({".exe"}))
        if effective.endswith(".exe"):
            with pytest.raises(ExtractionError):
                archive.safe_extractall(tmp_path, policy=policy)
            assert not list(tmp_path.iterdir())
        else:
            archive.safe_extractall(tmp_path, policy=policy)
            assert [path.name for path in tmp_path.iterdir()] == [effective]


@pytest.mark.parametrize("overwrite", list(OverwritePolicy))
@pytest.mark.parametrize("descriptor", [True, False])
def test_overwrite_policy_handles_file_created_during_extraction(
    tmp_path: Path,
    overwrite: OverwritePolicy,
    descriptor: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor:
        monkeypatch.setattr(os, "supports_dir_fd", set[str]())
    target = tmp_path / "file.txt"

    def create_conflict(_info: ZipInfo, _path: Path) -> None:
        target.write_bytes(b"concurrent content")

    # A custom validator runs after the overwrite assessment and before materialization.
    policy = ExtractPolicy(overwrite_policy=overwrite, custom_validator=create_conflict)
    with ZipFile(io.BytesIO(_archive(ZipInfo("file.txt")))) as archive:
        if overwrite == OverwritePolicy.ERROR:
            with pytest.raises(ExtractionError):
                archive.safe_extractall(tmp_path, policy=policy)
        else:
            result = archive.safe_extractall(tmp_path, policy=policy)
            if overwrite == OverwritePolicy.SKIP:
                assert result.skipped_count == 1
            elif overwrite == OverwritePolicy.RENAME:
                assert result.members[0].target == tmp_path / "file.1.txt"
                assert (tmp_path / "file.1.txt").read_bytes() == b"payload"
            else:
                assert result.members[0].overwritten
    expected = (
        b"payload" if overwrite == OverwritePolicy.REPLACE else b"concurrent content"
    )
    assert target.read_bytes() == expected
    assert not list(tmp_path.glob(".zipctl-*"))


@pytest.mark.skipif(os.name != "posix", reason="requires symlinks")
def test_symlink_target_cannot_escape_through_existing_link(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "bridge").symlink_to(tmp_path)
    info = ZipInfo("link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ZipFile(io.BytesIO(_archive(info, b"bridge/secret"))) as archive:
        with pytest.raises(ExtractionError):
            archive.safe_extractall(root, policy=ExtractPolicy(allow_symlinks=True))
    assert not (root / "link").is_symlink()


@pytest.mark.parametrize("limit", ["max_member_size", "max_total_uncompressed_size"])
def test_warn_size_limit_really_allows_extraction(tmp_path: Path, limit: str) -> None:
    policy = ExtractPolicy(
        max_member_size=3 if limit == "max_member_size" else None,
        max_total_uncompressed_size=3
        if limit == "max_total_uncompressed_size"
        else None,
        on_violation=ViolationAction.WARN,
    )
    with ZipFile(io.BytesIO(_archive(ZipInfo("file.txt")))) as archive:
        with pytest.warns(UserWarning, match="exceeds"):
            result = archive.safe_extractall(tmp_path, policy=policy)
    assert result.extracted_count == 1
    assert result.failed_count == 0


def test_corrupt_deflate_is_recorded_and_next_member_is_extracted(
    tmp_path: Path,
) -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=8) as archive:
        archive.writestr("bad", b"payload")
        archive.writestr("good", b"survives")
    data = bytearray(buffer.getvalue())
    data[33] = 7  # reserved DEFLATE block type
    with ZipFile(io.BytesIO(data)) as archive:
        with pytest.raises(ExtractionError) as caught:
            archive.safe_extractall(tmp_path, policy=ExtractPolicy())
    assert caught.value.result.failed_count == 1
    assert caught.value.result.extracted_count == 1
    assert (tmp_path / "good").read_bytes() == b"survives"
    assert not (tmp_path / "bad").exists()


@pytest.mark.skipif(os.name != "posix", reason="requires symlinks")
@pytest.mark.parametrize(
    "payload", [b"bad\x00target", b"x" * 65537], ids=["nul", "oversized"]
)
def test_invalid_symlink_preserves_existing_file(
    tmp_path: Path, payload: bytes
) -> None:
    target = tmp_path / "link"
    target.write_bytes(b"original")
    info = ZipInfo("link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ZipFile(io.BytesIO(_archive(info, payload))) as archive:
        with pytest.raises(ExtractionError):
            archive.safe_extractall(
                tmp_path,
                policy=ExtractPolicy(
                    allow_symlinks=True, overwrite_policy=OverwritePolicy.REPLACE
                ),
            )
    assert target.read_bytes() == b"original"
    assert not list(tmp_path.glob(".zipctl-*"))


@pytest.mark.skipif(os.name != "posix", reason="requires symlinks")
def test_dangling_symlink_counts_as_existing_target(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    target.symlink_to("missing")
    with ZipFile(io.BytesIO(_archive(ZipInfo("file.txt")))) as archive:
        with pytest.raises(ExtractionError):
            archive.safe_extractall(tmp_path, policy=ExtractPolicy())
    assert target.is_symlink()
    assert not (tmp_path / "missing").exists()


def test_extension_allowlist_does_not_reject_directories(tmp_path: Path) -> None:
    with ZipFile(io.BytesIO(_archive(ZipInfo("docs/"), b""))) as archive:
        result = archive.safe_extractall(
            tmp_path, policy=ExtractPolicy(allowed_extensions=frozenset({".txt"}))
        )
    assert result.extracted_count == 1
    assert (tmp_path / "docs").is_dir()


def test_rename_file_around_existing_directory(tmp_path: Path) -> None:
    (tmp_path / "file.txt").mkdir()
    with ZipFile(io.BytesIO(_archive(ZipInfo("file.txt")))) as archive:
        result = archive.safe_extractall(
            tmp_path, policy=ExtractPolicy(overwrite_policy=OverwritePolicy.RENAME)
        )
    assert result.members[0].target == tmp_path / "file.1.txt"
    assert (tmp_path / "file.txt").is_dir()


@pytest.mark.parametrize("action", [ViolationAction.ERROR, ViolationAction.SKIP])
def test_runtime_quota_keeps_rule_action(
    tmp_path: Path, action: ViolationAction
) -> None:
    def exceed(
        _info: ZipInfo,
        _target: Path,
        _quota: ExtractionQuota,
        _reporter: ProgressReporter | None,
    ) -> MaterializationResult:
        raise ExtractionQuotaExceeded("actual_member_size", 3)

    info = ZipInfo("file.txt")
    info.file_size = 1
    result = extract_with_policy(
        [info],
        tmp_path,
        tmp_path,
        ExtractPolicy(max_member_size=3, on_violation=action),
        exceed,
    )
    assert result.violations[-1].action == action
    assert result.skipped_count == int(action == ViolationAction.SKIP)
    assert result.failed_count == int(action == ViolationAction.ERROR)
