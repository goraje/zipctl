import dataclasses
from pathlib import Path
from typing import NoReturn

import pytest

import zipctl
from zipctl.compression import Registry, stored
from zipctl.zipfile.info import ZipInfo


def test_inspection_reports_metadata_findings_without_extraction(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "inspect.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("same.txt", b"one")
        zf.writestr("./same.txt", b"two")
        zf.writestr("../same.txt", b"escape")
        zf.writestr("large.bin", b"x" * 8)

    with zipctl.ZipFile(archive) as zf:
        report = zf.inspect(
            tmp_path / "not-created",
            zipctl.ExtractPolicy(
                max_member_size=4,
                max_compression_ratio=None,
                on_violation=zipctl.ViolationAction.SKIP,
            ),
        )

    assert report.total_entries == 4
    assert report.total_compressed_size > 0
    assert report.total_uncompressed_size == 20
    assert report.duplicate_targets == (tmp_path / "not-created" / "same.txt",)
    assert report.suspicious_paths == ("../same.txt",)
    assert report.large_members == ("../same.txt", "large.bin")
    assert report.members[2].violations[0].action == zipctl.ViolationAction.SKIP
    assert not (tmp_path / "not-created").exists()


def test_inspection_distinguishes_symlinks_and_special_files(tmp_path: Path) -> None:
    archive = tmp_path / "types.zip"
    link = ZipInfo("link")
    link.external_attr = (0o120777 << 16) | 0xA000
    special = ZipInfo("device")
    special.external_attr = 0o010000 << 16
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr(link, "target")
        zf.writestr(special, b"data")

    with zipctl.ZipFile(archive) as zf:
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
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("payload.txt", b"payload")

    def forbidden(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("inspection opened a payload")

    with zipctl.ZipFile(archive) as zf:
        monkeypatch.setattr(zf, "open", forbidden)
        report = zf.inspect(tmp_path / "output")

    assert report.members[0].member == "payload.txt"
    assert sentinel.read_text() == "unchanged"
    assert not (tmp_path / "output").exists()


def test_assess_returns_shared_archive_assessment(tmp_path: Path) -> None:
    archive = tmp_path / "assessment.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("payload.txt", b"payload")

    with zipctl.ZipFile(archive) as zf:
        assessment = zf.assess(tmp_path / "output")

    assert assessment.total_uncompressed_size == len(b"payload")
    assert assessment.members[0].info.filename == "payload.txt"
    assert not (tmp_path / "output").exists()


def test_assess_reports_archive_wide_policy_violations(tmp_path: Path) -> None:
    archive = tmp_path / "assessment-limits.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("first.txt", b"1234567890")
        zf.writestr("second.txt", b"more")

    with zipctl.ZipFile(archive) as zf:
        assessment = zf.assess(
            tmp_path / "output",
            zipctl.ExtractPolicy(
                max_entries=1,
                max_total_uncompressed_size=5,
                max_compression_ratio=None,
                on_violation=zipctl.ViolationAction.SKIP,
            ),
        )

    codes = {v.code for v in assessment.violations}
    assert "max_entries" in codes
    assert "max_total_uncompressed_size" in codes
    assert not (tmp_path / "output").exists()


def _archive_with_late_escape(tmp_path: Path) -> Path:
    archive = tmp_path / "limit.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("first.txt", b"one")
        zf.writestr("../escape.txt", b"far")
    return archive


@pytest.mark.parametrize(
    "action", [zipctl.ViolationAction.SKIP, zipctl.ViolationAction.ERROR]
)
def test_inspection_stops_assessing_at_the_entry_limit(
    tmp_path: Path, action: zipctl.ViolationAction
) -> None:
    policy = zipctl.ExtractPolicy(max_entries=1, on_violation=action)
    with zipctl.ZipFile(_archive_with_late_escape(tmp_path)) as zf:
        report = zf.inspect(tmp_path / "out", policy)

    assert [m.assessed for m in report.members] == [True, False]
    assert report.members[1].violations == ()
    assert report.members[1].target is None
    assert report.suspicious_paths == ()
    assert report.total_uncompressed_size == 3
    assert [v.member for v in report.violations] == ["<archive>"]


def test_extraction_skips_what_inspection_did_not_assess(tmp_path: Path) -> None:
    policy = zipctl.ExtractPolicy(
        max_entries=1, on_violation=zipctl.ViolationAction.SKIP
    )
    with zipctl.ZipFile(_archive_with_late_escape(tmp_path)) as zf:
        result = zf.safe_extractall(tmp_path / "out", policy=policy)

    assert result.extracted_count == 1
    assert result.skipped_count == 1
    assert result.members[1].violations == ()


def test_a_refused_archive_leaves_unassessed_members_without_findings(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "refused.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", b"far")
        zf.writestr("late.txt", b"two")
    policy = zipctl.ExtractPolicy(
        max_entries=zipctl.ExtractPolicyRule(1, zipctl.ViolationAction.SKIP)
    )
    with zipctl.ZipFile(archive) as zf, pytest.raises(zipctl.ExtractionError) as raised:
        zf.safe_extractall(tmp_path / "out", policy=policy)

    late = raised.value.result.members[1]
    assert late.status == zipctl.MemberStatus.SKIPPED
    assert late.violations == ()


def test_inspection_totals_sum_every_assessed_member(tmp_path: Path) -> None:
    archive = tmp_path / "totals.zip"
    with zipctl.ZipFile(archive, "w", zipctl.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", b"a" * 100)
        zf.writestr("b.txt", b"b" * 50)
    with zipctl.ZipFile(archive) as zf:
        report = zf.inspect(tmp_path / "out")
        infos = zf.infolist()

    assert report.total_compressed_size == sum(i.compress_size for i in infos)
    assert report.total_uncompressed_size == 150


def test_an_archive_at_the_entry_limit_is_within_it(tmp_path: Path) -> None:
    with zipctl.ZipFile(_archive_with_late_escape(tmp_path)) as zf:
        report = zf.inspect(tmp_path / "out", zipctl.ExtractPolicy(max_entries=2))

    assert not report.member_count_over_limit
    assert all(member.assessed for member in report.members)


def test_a_refused_archive_reports_its_destination(tmp_path: Path) -> None:
    with (
        zipctl.ZipFile(_archive_with_late_escape(tmp_path)) as zf,
        pytest.raises(zipctl.ExtractionError) as raised,
    ):
        zf.safe_extractall(tmp_path / "out")

    assert raised.value.result.destination == tmp_path / "out"
    assert raised.value.result.members[0].bytes_written == 0


def test_extraction_assesses_with_the_archive_registry(tmp_path: Path) -> None:
    custom = Registry()
    custom.register(
        95, dataclasses.replace(stored.compression_entry, compression_method=95)
    )
    archive = tmp_path / "custom.zip"
    with zipctl.ZipFile(archive, "w", 95, compression_registry=custom) as zf:
        zf.writestr("a.txt", b"data")

    with zipctl.ZipFile(archive, compression_registry=custom) as zf:
        result = zf.safe_extractall(
            tmp_path / "out", policy=zipctl.ExtractPolicy(preview_only=True)
        )

    assert result.previewed_count == 1
