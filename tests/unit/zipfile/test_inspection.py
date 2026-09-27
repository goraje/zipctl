from pathlib import Path
from typing import NoReturn

import pytest

import ziplet
from ziplet.zipfile.info import ZipInfo


def test_inspection_reports_metadata_findings_without_extraction(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "inspect.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("same.txt", b"one")
        with pytest.warns(UserWarning, match="Duplicate name: 'same.txt'"):
            zf.writestr("same.txt", b"two")
        zf.writestr("../same.txt", b"escape")
        zf.writestr("large.bin", b"x" * 8)

    with ziplet.ZipFile(archive) as zf:
        report = zf.inspect(
            tmp_path / "not-created",
            ziplet.ExtractPolicy(
                max_member_size=4,
                max_compression_ratio=None,
                on_violation=ziplet.ViolationAction.SKIP,
            ),
        )

    assert report.total_entries == 4
    assert report.total_compressed_size > 0
    assert report.total_uncompressed_size == 20
    assert report.duplicate_member_names == ("same.txt",)
    assert report.duplicate_targets == (tmp_path / "not-created" / "same.txt",)
    assert report.suspicious_paths == ("../same.txt",)
    assert report.large_members == ("../same.txt", "large.bin")
    assert report.members[2].violations[0].action == ziplet.ViolationAction.SKIP
    assert not (tmp_path / "not-created").exists()


def test_inspection_distinguishes_symlinks_and_special_files(tmp_path: Path) -> None:
    archive = tmp_path / "types.zip"
    link = ZipInfo("link")
    link.external_attr = (0o120777 << 16) | 0xA000
    special = ZipInfo("device")
    special.external_attr = 0o010000 << 16
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr(link, "target")
        zf.writestr(special, b"data")

    with ziplet.ZipFile(archive) as zf:
        report = zf.inspect()

    assert report.symlinks == ("link",)
    assert report.special_files == ("device",)
    assert any(v.code == "symlink" for v in report.members[0].violations)


def test_inspection_does_not_open_payloads_or_modify_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "metadata-only.zip"
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("unchanged")
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("payload.txt", b"payload")

    def forbidden(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("inspection opened a payload")

    with ziplet.ZipFile(archive) as zf:
        monkeypatch.setattr(zf, "open", forbidden)
        report = zf.inspect(tmp_path / "output")

    assert report.members[0].member == "payload.txt"
    assert sentinel.read_text() == "unchanged"
    assert not (tmp_path / "output").exists()


def test_assess_returns_shared_archive_assessment(tmp_path: Path) -> None:
    archive = tmp_path / "assessment.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("payload.txt", b"payload")

    with ziplet.ZipFile(archive) as zf:
        assessment = zf.assess(tmp_path / "output")

    assert assessment.total_uncompressed_size == len(b"payload")
    assert assessment.members[0].info.filename == "payload.txt"
    assert not (tmp_path / "output").exists()


def test_assess_reports_archive_wide_policy_violations(tmp_path: Path) -> None:
    archive = tmp_path / "assessment-limits.zip"
    with ziplet.ZipFile(archive, "w") as zf:
        zf.writestr("first.txt", b"1234567890")
        zf.writestr("second.txt", b"more")

    with ziplet.ZipFile(archive) as zf:
        assessment = zf.assess(
            tmp_path / "output",
            ziplet.ExtractPolicy(
                max_entries=1,
                max_total_uncompressed_size=5,
                max_compression_ratio=None,
                on_violation=ziplet.ViolationAction.SKIP,
            ),
        )

    codes = {v.code for v in assessment.violations}
    assert "max_entries" in codes
    assert "max_total_uncompressed_size" in codes
    assert not (tmp_path / "output").exists()
