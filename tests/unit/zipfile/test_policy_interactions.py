"""Policy construction, target renaming, archive order and extraction failures."""

import io
import os
from pathlib import Path
from typing import cast

import pytest
from typing_extensions import override

import zipctl
from tests.unit.zipfile.archive_factory import archive_bytes
from zipctl import (
    ExtractionError,
    ExtractPolicy,
    OverwritePolicy,
    PolicyConfigError,
    ZipFile,
    ZipInfo,
)


def test_directory_after_child_preserves_archive_order(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("dir/file", b"payload")
        archive.mkdir("dir")
    with ZipFile(buffer) as archive:
        result = archive.safe_extractall(tmp_path, policy=ExtractPolicy())
    assert result.failed_count == 0
    assert [member.member for member in result.members] == ["dir/file", "dir/"]
    assert (tmp_path / "dir/file").read_bytes() == b"payload"


def test_rename_preserves_extensions_and_rechecks_custom_rules(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    target.write_bytes(b"original")
    visited: list[str] = []

    def validate(_info: ZipInfo, candidate: Path) -> None:
        visited.append(candidate.name)
        if candidate.name == "file.1.txt":
            raise ValueError("renamed target disallowed")

    policy = ExtractPolicy(
        overwrite_policy=OverwritePolicy.RENAME,
        allowed_extensions=frozenset({".TXT"}),
        custom_validator=validate,
    )
    with ZipFile(io.BytesIO(archive_bytes())) as archive:
        with pytest.raises(ExtractionError):
            archive.safe_extractall(tmp_path, policy=policy)
    assert visited == ["file.txt", "file.1.txt"]
    assert target.read_bytes() == b"original"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["file.txt"]


@pytest.mark.parametrize("value", [-1, True, 1.5])
def test_direct_policy_rejects_invalid_limits(value: object) -> None:
    with pytest.raises(PolicyConfigError):
        ExtractPolicy(max_entries=value)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]  # ty: ignore[invalid-argument-type]


def test_policy_construction_and_json_normalize_equally() -> None:
    direct = ExtractPolicy(blocked_extensions=frozenset({".EXE", ".Tar.GZ"}))
    parsed = zipctl.policy_from_json('{"blocked_extensions":[".EXE",".Tar.GZ"]}')
    assert direct == parsed
    with pytest.raises(PolicyConfigError):
        ExtractPolicy(max_compression_ratio=float("nan"))


def test_filesystem_without_hardlinks_still_never_clobbers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unsupported(*_args: object, **_kwargs: object) -> None:
        raise OSError("hard links unavailable")

    monkeypatch.setattr(os, "link", unsupported)
    (tmp_path / "file.txt").write_bytes(b"original")
    with ZipFile(io.BytesIO(archive_bytes())) as archive:
        with pytest.raises(ExtractionError):
            archive.safe_extractall(tmp_path, policy=ExtractPolicy())
    assert [p.name for p in tmp_path.iterdir()] == ["file.txt"]
    assert (tmp_path / "file.txt").read_bytes() == b"original"


def test_interrupted_extraction_cleans_partial_file(tmp_path: Path) -> None:
    def interrupt(event: zipctl.ProgressEvent) -> None:
        if event.phase == zipctl.ProgressPhase.START:
            return
        raise KeyboardInterrupt

    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("file", b"x" * (2 << 20))
    with ZipFile(buffer) as archive:
        with pytest.raises(KeyboardInterrupt):
            archive.extractall(tmp_path, progress=interrupt)
    assert list(tmp_path.iterdir()) == []


def test_bad_write_argument_does_not_poison_a_nonseekable_archive() -> None:
    class Sink(io.BytesIO):
        @override
        def seekable(self) -> bool:
            return False

    with ZipFile(Sink(), "w") as archive:
        with archive.open("a", "w") as member:
            with pytest.raises(TypeError):
                member.write(cast("bytes", cast("object", "text")))
            member.write(b"ok")
