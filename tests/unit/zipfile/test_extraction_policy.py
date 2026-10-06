from __future__ import annotations

import io
import os
import stat
from pathlib import Path

import pytest

import zipctl
from zipctl.zipfile import validators
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.policy import ExtractionError
from zipctl.zipfile.secure_fs import SecureExtractionRoot


def test_policy_error_exposes_partial_result(tmp_path: Path) -> None:
    archive = tmp_path / "error.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", b"blocked")

    with zipctl.ZipFile(archive) as zf:
        with pytest.raises(ExtractionError) as raised:
            zf.safe_extractall(
                tmp_path / "out",
                policy=zipctl.ExtractPolicy(max_compression_ratio=None),
            )

    assert raised.value.result.failed_count == 1
    assert raised.value.result.members[0].status == zipctl.MemberStatus.FAILED


def test_policy_rename_does_not_overwrite_existing_target(tmp_path: Path) -> None:
    archive = tmp_path / "rename.zip"
    output = tmp_path / "out"
    output.mkdir()
    (output / "file.txt").write_bytes(b"original")
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("file.txt", b"new")

    with zipctl.ZipFile(archive) as zf:
        result = zf.safe_extractall(
            output,
            policy=zipctl.ExtractPolicy(
                max_compression_ratio=None,
                overwrite_policy=zipctl.OverwritePolicy.RENAME,
            ),
        )

    assert result.members[0].target == output / "file.1.txt"
    assert (output / "file.txt").read_bytes() == b"original"
    assert (output / "file.1.txt").read_bytes() == b"new"


def test_a_directory_member_merges_into_an_existing_directory(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "dirs.zip"
    output = tmp_path / "out"
    (output / "src").mkdir(parents=True)
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("src/", b"")
        zf.writestr("src/a.txt", b"a")

    with zipctl.ZipFile(archive) as zf:
        result = zf.safe_extractall(output)

    assert not result.violations
    assert (output / "src" / "a.txt").read_bytes() == b"a"


@pytest.mark.skipif(os.name != "posix", reason="needs symlinks")
def test_a_directory_member_onto_a_symlink_is_still_a_conflict(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "dirs.zip"
    output = tmp_path / "out"
    output.mkdir()
    (output / "real").mkdir()
    (output / "src").symlink_to("real")
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("src/", b"")

    with zipctl.ZipFile(archive) as zf, pytest.raises(ExtractionError):
        zf.safe_extractall(output)


def test_policy_enforces_member_quota_before_writing(tmp_path: Path) -> None:
    archive = tmp_path / "member-limit.zip"
    output = tmp_path / "out"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("large.bin", b"x" * 32)

    with zipctl.ZipFile(archive) as zf:
        result = zf.safe_extractall(
            output,
            policy=zipctl.ExtractPolicy(
                max_member_size=16,
                max_compression_ratio=None,
                on_violation=zipctl.ViolationAction.SKIP,
            ),
        )

    assert result.members[0].status == zipctl.MemberStatus.SKIPPED
    assert result.members[0].bytes_written == 0
    assert not (output / "large.bin").exists()


def test_policy_enforces_total_quota_across_members(tmp_path: Path) -> None:
    archive = tmp_path / "total-limit.zip"
    output = tmp_path / "out"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("one.bin", b"1" * 8)
        zf.writestr("two.bin", b"2" * 8)

    with zipctl.ZipFile(archive) as zf:
        result = zf.safe_extractall(
            output,
            policy=zipctl.ExtractPolicy(
                max_member_size=None,
                max_total_uncompressed_size=12,
                max_compression_ratio=None,
                on_violation=zipctl.ViolationAction.SKIP,
            ),
        )

    assert [member.status for member in result.members] == [
        zipctl.MemberStatus.EXTRACTED,
        zipctl.MemberStatus.SKIPPED,
    ]
    assert result.bytes_written == 8
    assert not (output / "two.bin").exists()


def test_policy_aborts_and_removes_partial_output_on_runtime_quota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "runtime-limit.zip"
    output = tmp_path / "out"
    with zipctl.ZipFile(archive, "w") as writer:
        writer.writestr("payload.bin", b"declared")

    def oversized_open(*_args: object, **_kwargs: object) -> io.BytesIO:
        return io.BytesIO(b"x" * 32)

    with zipctl.ZipFile(archive) as zf:
        monkeypatch.setattr(zf, "open", oversized_open)
        with pytest.raises(ExtractionError) as raised:
            zf.safe_extractall(
                output,
                policy=zipctl.ExtractPolicy(
                    max_member_size=16,
                    max_compression_ratio=None,
                ),
            )

    result = raised.value.result
    assert result.members[0].status == zipctl.MemberStatus.FAILED
    assert any(v.code == "actual_member_size" for v in result.violations)
    assert not (output / "payload.bin").exists()


def test_policy_extracts_mixed_archive_with_member_results(tmp_path: Path) -> None:
    archive = tmp_path / "policy.zip"
    destination = tmp_path / "extracted"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("docs/readme.txt", b"readme")
        zf.writestr("data.bin", b"data")
        zf.writestr("../outside.txt", b"blocked")

    with zipctl.ZipFile(archive) as zf:
        result = zf.safe_extractall(
            destination,
            policy=zipctl.ExtractPolicy(
                max_compression_ratio=None,
                on_violation=zipctl.ViolationAction.SKIP,
            ),
        )

    assert result.extracted_count == 2
    assert result.skipped_count == 1
    assert [member.status for member in result.members] == [
        zipctl.MemberStatus.EXTRACTED,
        zipctl.MemberStatus.EXTRACTED,
        zipctl.MemberStatus.SKIPPED,
    ]
    assert any(v.code == "parent_traversal" for v in result.violations)
    assert (destination / "docs/readme.txt").read_bytes() == b"readme"
    assert (destination / "data.bin").read_bytes() == b"data"
    assert not (tmp_path / "outside.txt").exists()


def test_policy_preview_is_a_real_dry_run(tmp_path: Path) -> None:
    archive = tmp_path / "preview.zip"
    destination = tmp_path / "preview"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("file.txt", b"payload")

    with zipctl.ZipFile(archive) as zf:
        result = zf.safe_extractall(
            destination,
            policy=zipctl.ExtractPolicy(
                max_compression_ratio=None,
                preview_only=True,
            ),
        )

    assert result.preview_only
    assert (result.extracted_count, result.skipped_count) == (0, 0)
    assert result.previewed_count == 1
    assert result.members[0].status == zipctl.MemberStatus.PREVIEWED
    assert not destination.exists()


def test_a_run_opens_its_destination_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[SecureExtractionRoot] = []
    enter = SecureExtractionRoot.__enter__

    def recording_enter(self: SecureExtractionRoot) -> SecureExtractionRoot:
        opened.append(self)
        return enter(self)

    monkeypatch.setattr(SecureExtractionRoot, "__enter__", recording_enter)
    archive = io.BytesIO()
    with zipctl.ZipFile(archive, "w") as zf:
        for name in ("a.txt", "d/b.txt", "d/e/c.txt"):
            zf.writestr(name, b"x")
    with zipctl.ZipFile(archive) as zf:
        zf.extractall(tmp_path / "out")

    assert (tmp_path / "out" / "d" / "e" / "c.txt").read_bytes() == b"x"
    assert len(opened) == 1
    assert opened[0]._descriptor is None  # closed when the run ends


def test_error_quota_preserves_existing_file(tmp_path: Path) -> None:
    archive = tmp_path / "quota.zip"
    destination = tmp_path / "out"
    destination.mkdir()
    existing = destination / "second.txt"
    existing.write_bytes(b"original")

    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("first.txt", b"1234")
        zf.writestr("second.txt", b"replacement")

    with zipctl.ZipFile(archive) as zf:
        with pytest.raises(zipctl.ExtractionError):
            zf.safe_extractall(
                destination,
                policy=zipctl.ExtractPolicy(
                    max_total_uncompressed_size=5,
                    overwrite_policy=zipctl.OverwritePolicy.REPLACE,
                ),
            )

    assert existing.read_bytes() == b"original"
    assert not list(destination.glob(".zipctl-*"))


@pytest.mark.skipif(os.name != "posix", reason="needs symlinks")
def test_allowed_symlink_is_materialized_without_following_it(tmp_path: Path) -> None:
    archive = tmp_path / "symlink.zip"
    destination = tmp_path / "out"
    info = ZipInfo("link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr(info, b"target.txt")

    with zipctl.ZipFile(archive) as zf:
        result = zf.safe_extractall(
            destination,
            policy=zipctl.ExtractPolicy(
                allow_symlinks=True,
                max_compression_ratio=None,
            ),
        )

    link = destination / "link"
    assert result.extracted_count == 1
    assert link.is_symlink()
    assert os.readlink(link) == "target.txt"


def test_warn_still_rejects_path_escape(tmp_path: Path) -> None:
    archive = tmp_path / "escape.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("../outside.txt", b"blocked")

    with zipctl.ZipFile(archive) as zf:
        with pytest.raises(zipctl.ExtractionError):
            zf.safe_extractall(
                tmp_path / "out",
                policy=zipctl.ExtractPolicy(
                    on_violation=zipctl.ViolationAction.WARN,
                    max_compression_ratio=None,
                ),
            )
    assert not (tmp_path / "outside.txt").exists()


def test_extract_policy_rule_overrides_default_violation_action(tmp_path: Path) -> None:
    archive = tmp_path / "rule-override.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("safe.txt", b"safe")
        zf.writestr("/absolute.txt", b"blocked-by-default")
        zf.writestr("../escape.txt", b"blocked-by-rule")

    with zipctl.ZipFile(archive) as zf:
        with pytest.raises(zipctl.ExtractionError) as excinfo:
            zf.safe_extractall(
                tmp_path / "out",
                policy=zipctl.ExtractPolicy(
                    max_compression_ratio=None,
                    on_violation=zipctl.ViolationAction.SKIP,
                    allow_parent_traversal=zipctl.ExtractPolicyRule(
                        False, on_violation=zipctl.ViolationAction.ERROR
                    ),
                ),
            )

    result = excinfo.value.result
    assert result.extracted_count == 0  # an error anywhere refuses the archive
    assert result.skipped_count == 2
    assert result.failed_count == 1
    actions_by_code = {v.code: v.action for v in result.violations}
    assert actions_by_code["absolute_path"] == zipctl.ViolationAction.SKIP
    assert actions_by_code["parent_traversal"] == zipctl.ViolationAction.ERROR


@pytest.mark.skipif(os.name != "posix", reason="POSIX umask")
def test_plain_extract_honours_umask(tmp_path: Path) -> None:
    archive = tmp_path / "mode.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("f.txt", b"x")
    previous = os.umask(0o022)
    try:
        with zipctl.ZipFile(archive) as zf:
            zf.extract("f.txt", tmp_path / "out")
    finally:
        os.umask(previous)
    assert stat.S_IMODE((tmp_path / "out" / "f.txt").stat().st_mode) == 0o644


def test_extract_policy_marks_overwritten_members(tmp_path: Path) -> None:
    archive = tmp_path / "overwrite.zip"
    destination = tmp_path / "out"
    destination.mkdir()
    (destination / "existing.txt").write_bytes(b"stale")
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("existing.txt", b"fresh")
        zf.writestr("new.txt", b"new")

    with zipctl.ZipFile(archive) as zf:
        result = zf.safe_extractall(
            destination,
            policy=zipctl.ExtractPolicy(
                max_compression_ratio=None,
                overwrite_policy=zipctl.OverwritePolicy.REPLACE,
            ),
        )

    results_by_name = {r.member: r for r in result.members}
    assert results_by_name["existing.txt"].overwritten is True
    assert results_by_name["new.txt"].overwritten is False
    assert (destination / "existing.txt").read_bytes() == b"fresh"


def test_extract_returns_an_empty_string_for_a_skipped_member(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"new")

    with zipctl.ZipFile(buffer) as zf:
        extracted = zf.extract(
            "a.txt",
            tmp_path,
            policy=zipctl.ExtractPolicy(overwrite_policy=zipctl.OverwritePolicy.SKIP),
        )

    assert extracted == ""
    assert (tmp_path / "a.txt").read_bytes() == b"old"


def test_extract_returns_the_would_be_path_under_preview(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"new")

    with zipctl.ZipFile(buffer) as zf:
        extracted = zf.extract(
            "a.txt", tmp_path, policy=zipctl.ExtractPolicy(preview_only=True)
        )

    assert extracted == str(tmp_path / "a.txt")
    assert not (tmp_path / "a.txt").exists()


@pytest.mark.skipif(os.name != "posix", reason="needs symlinks")
def test_dir_fd_relative_regular_file_replaces_leaf_symlink_without_following(
    tmp_path: Path,
) -> None:
    """Regular-file materialization now also goes through the dir_fd-relative
    path (rename relative to the validated parent). A pre-existing symlink
    at the leaf name must be replaced outright, never followed to write
    through it to wherever it points."""
    archive = tmp_path / "leaf-symlink-file.zip"
    destination = tmp_path / "out"
    destination.mkdir()
    # Inside the destination: a link that leads out is refused before this.
    outside = destination / "linked.txt"
    outside.write_bytes(b"original-outside-content")
    (destination / "payload.txt").symlink_to(outside)
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("payload.txt", b"new-content")

    with zipctl.ZipFile(archive) as zf:
        zf.extract(
            "payload.txt",
            destination,
            policy=zipctl.ExtractPolicy(
                overwrite_policy=zipctl.OverwritePolicy.REPLACE
            ),
        )

    assert not (destination / "payload.txt").is_symlink()
    assert (destination / "payload.txt").read_bytes() == b"new-content"
    assert outside.read_bytes() == b"original-outside-content"


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX directories")
@pytest.mark.parametrize(
    ("fsync_files", "expected"), [(True, [False, False, True]), (False, [])]
)
def test_fsync_files_policy_controls_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fsync_files: bool,
    expected: list[bool],
) -> None:
    archive = tmp_path / "a.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("one.txt", b"1")
        zf.writestr("two.txt", b"2")
    calls: list[bool] = []  # whether each fsync was of a directory
    real_fsync = os.fsync

    def recording_fsync(fd: int) -> None:
        calls.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", recording_fsync)

    with zipctl.ZipFile(archive) as zf:
        zf.safe_extractall(
            tmp_path / "out", policy=zipctl.ExtractPolicy(fsync_files=fsync_files)
        )

    # each file before its rename, then their shared directory once
    assert calls == expected
    assert (tmp_path / "out" / "two.txt").read_bytes() == b"2"


def _five_entry_archive() -> io.BytesIO:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        for index in range(5):
            zf.writestr(f"f{index}.txt", b"x")
    return io.BytesIO(buffer.getvalue())


def _count_violations(result: zipctl.ExtractResult) -> list[str]:
    return [v.member for v in result.violations if v.code == "max_entries"]


def test_max_entries_error_extracts_nothing_and_reports_once(tmp_path: Path) -> None:
    policy = zipctl.ExtractPolicy(max_entries=3)
    with zipctl.ZipFile(_five_entry_archive()) as zf:
        with pytest.raises(zipctl.ExtractionError) as excinfo:
            zf.safe_extractall(tmp_path / "out", policy=policy)

    result = excinfo.value.result
    assert not (tmp_path / "out").exists() or not list((tmp_path / "out").iterdir())
    assert (result.extracted_count, result.failed_count) == (0, 5)
    assert _count_violations(result) == ["<archive>"]
    assert all(m.status == zipctl.MemberStatus.FAILED for m in result.members)
    assert all(m.target is None for m in result.members)
    assert all(m.violations == result.violations for m in result.members)


def test_max_entries_skip_extracts_only_the_first_entries(tmp_path: Path) -> None:
    policy = zipctl.ExtractPolicy(
        max_entries=3, on_violation=zipctl.ViolationAction.SKIP
    )
    with zipctl.ZipFile(_five_entry_archive()) as zf:
        result = zf.safe_extractall(tmp_path, policy=policy)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["f0.txt", "f1.txt", "f2.txt"]
    assert (result.extracted_count, result.skipped_count) == (3, 2)
    assert _count_violations(result) == ["<archive>"]


def test_max_entries_warn_extracts_everything_with_one_warning(tmp_path: Path) -> None:
    policy = zipctl.ExtractPolicy(
        max_entries=3, on_violation=zipctl.ViolationAction.WARN
    )
    with zipctl.ZipFile(_five_entry_archive()) as zf:
        with pytest.warns(UserWarning, match="limit is 3") as caught:
            result = zf.safe_extractall(tmp_path, policy=policy)

    assert len(caught) == 1
    assert result.extracted_count == 5
    assert _count_violations(result) == ["<archive>"]


def test_inspection_reports_entry_count_once() -> None:
    policy = zipctl.ExtractPolicy(max_entries=3)
    with zipctl.ZipFile(_five_entry_archive()) as zf:
        report = zf.inspect(policy=policy)

    assert report.member_count_over_limit
    assert [v.member for v in report.violations if v.code == "max_entries"] == [
        "<archive>"
    ]


def _reject_temp_files(info: ZipInfo, _target: Path) -> None:
    if info.filename.endswith(".tmp"):
        raise ValueError(f"{info.filename}: temporary files are not allowed")


def _reject_large_names(info: ZipInfo, _target: Path) -> None:
    if len(info.filename) > 8:
        raise ValueError(f"{info.filename}: name is too long")


def _custom_archive() -> io.BytesIO:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("ok.txt", b"1")
        zf.writestr("a.tmp", b"2")
        zf.writestr("very_long_name.tmp", b"3")
    return io.BytesIO(buffer.getvalue())


def _custom_messages(assessment: zipctl.ArchiveAssessment) -> list[str]:
    return [v.message for v in assessment.violations if v.code == "custom_validator"]


def test_single_custom_validator_still_works(tmp_path: Path) -> None:
    policy = zipctl.ExtractPolicy(custom_validator=_reject_temp_files)
    with zipctl.ZipFile(_custom_archive()) as zf:
        assessment = zf.assess(tmp_path, policy)
    assert _custom_messages(assessment) == [
        "a.tmp: temporary files are not allowed",
        "very_long_name.tmp: temporary files are not allowed",
    ]


def test_custom_validator_chain_reports_every_rejection(tmp_path: Path) -> None:
    policy = zipctl.ExtractPolicy(
        custom_validator=(_reject_temp_files, _reject_large_names)
    )
    with zipctl.ZipFile(_custom_archive()) as zf:
        assessment = zf.assess(tmp_path, policy)
    assert _custom_messages(assessment) == [
        "a.tmp: temporary files are not allowed",
        "very_long_name.tmp: temporary files are not allowed",
        "very_long_name.tmp: name is too long",
    ]
    ok, temp, long_temp = assessment.members
    assert not ok.violations
    assert len(temp.violations) == 1
    assert len(long_temp.violations) == 2


def test_custom_validator_chain_can_skip_members(tmp_path: Path) -> None:
    policy = zipctl.ExtractPolicy(
        custom_validator=[_reject_temp_files, _reject_large_names],
        on_violation=zipctl.ViolationAction.SKIP,
    )
    with zipctl.ZipFile(_custom_archive()) as zf:
        result = zf.safe_extractall(tmp_path, policy=policy)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ok.txt"]
    assert (result.extracted_count, result.skipped_count) == (1, 2)


def test_custom_validator_unexpected_error_propagates(tmp_path: Path) -> None:
    def broken(_info: ZipInfo, _target: Path) -> None:
        raise KeyError("bug in validator")

    with zipctl.ZipFile(_custom_archive()) as zf:
        with pytest.raises(KeyError):
            zf.assess(tmp_path, zipctl.ExtractPolicy(custom_validator=broken))


def test_policy_extractall_refuses_duplicate_targets_writing_nothing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "dup.zip"
    with zipctl.ZipFile(path, "w") as zf:
        zf.writestr("same.txt", b"first")
        zf.writestr("./same.txt", b"second")
    with zipctl.ZipFile(path) as zf, pytest.raises(zipctl.ExtractionError):
        zf.safe_extractall(tmp_path / "out", policy=zipctl.ExtractPolicy())
    assert not (tmp_path / "out").exists()


def _symlink(name: str) -> ZipInfo:
    info = ZipInfo(name)
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return info


def test_a_path_through_an_earlier_file_member_is_refused_before_writing(
    tmp_path: Path,
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("first.txt", b"first")
        zf.writestr("a", b"a")
        zf.writestr("a/b", b"b")
    output = tmp_path / "out"

    with zipctl.ZipFile(buffer) as zf:
        found = [(v.member, v.code) for v in zf.assess(output).violations]
        with pytest.raises(ExtractionError):
            zf.safe_extractall(output)
    assert found == [("a/b", "parent_conflict")]
    assert not output.exists()


@pytest.mark.parametrize(
    "overwrite", [zipctl.OverwritePolicy.ERROR, zipctl.OverwritePolicy.REPLACE]
)
@pytest.mark.parametrize(
    "link",
    [
        False,
        pytest.param(
            True, marks=pytest.mark.skipif(os.name != "posix", reason="symlinks")
        ),
    ],
    ids=["file", "symlink"],
)
def test_a_member_on_a_directory_an_earlier_member_needs_is_refused_before_writing(
    tmp_path: Path, overwrite: zipctl.OverwritePolicy, link: bool
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("first.txt", b"first")
        zf.writestr("a/b", b"b")
        zf.writestr(_symlink("a") if link else "a", b"first.txt")
    policy = zipctl.ExtractPolicy(overwrite_policy=overwrite, allow_symlinks=True)
    output = tmp_path / "out"

    with zipctl.ZipFile(buffer) as zf:
        found = [(v.member, v.code) for v in zf.assess(output, policy).violations]
        with pytest.raises(ExtractionError):
            zf.safe_extractall(output, policy=policy)
    assert found == [("a", "parent_conflict")]
    assert not output.exists()


@pytest.mark.parametrize(
    ("overwrite", "name", "status"),
    [
        (zipctl.OverwritePolicy.SKIP, "a", zipctl.MemberStatus.SKIPPED),
        (zipctl.OverwritePolicy.RENAME, "a.1", zipctl.MemberStatus.EXTRACTED),
    ],
)
def test_a_member_on_a_directory_an_earlier_member_needs_follows_the_policy(
    tmp_path: Path,
    overwrite: zipctl.OverwritePolicy,
    name: str,
    status: zipctl.MemberStatus,
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a/b", b"b")
        zf.writestr("a", b"a")
    output = tmp_path / "out"

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(
            output, policy=zipctl.ExtractPolicy(overwrite_policy=overwrite)
        )
    last = result.members[-1]
    assert (last.target, last.status) == (output / name, status)
    assert (output / "a" / "b").read_bytes() == b"b"


@pytest.mark.parametrize(
    "directory_entry", [False, True], ids=["alone", "under-a-directory-entry"]
)
def test_a_path_through_a_file_on_disk_is_refused_before_writing(
    tmp_path: Path, directory_entry: bool
) -> None:
    output = tmp_path / "out"
    output.mkdir()
    (output / "a").write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("z.txt", b"z")
        if directory_entry:
            zf.mkdir("a")
        zf.writestr("a/b", b"b")
    # SKIP leaves the file "a" in place for "a/" to skip: only "a/b" is an error.
    policy = zipctl.ExtractPolicy(overwrite_policy=zipctl.OverwritePolicy.SKIP)

    with zipctl.ZipFile(buffer) as zf:
        found = [
            (v.member, v.code)
            for v in zf.assess(output, policy).violations
            if v.action == zipctl.ViolationAction.ERROR
        ]
        with pytest.raises(ExtractionError):
            zf.safe_extractall(output, policy=policy)
    assert found == [("a/b", "parent_conflict")]
    assert not (output / "z.txt").exists()


@pytest.mark.parametrize(
    "overwrite", [zipctl.OverwritePolicy.SKIP, zipctl.OverwritePolicy.RENAME]
)
def test_a_file_member_on_a_directory_on_disk_leaves_the_path_through_it(
    tmp_path: Path, overwrite: zipctl.OverwritePolicy
) -> None:
    output = tmp_path / "out"
    (output / "a").mkdir(parents=True)
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a", b"a")
        zf.writestr("a/b", b"b")

    with zipctl.ZipFile(buffer) as zf:
        zf.safe_extractall(
            output, policy=zipctl.ExtractPolicy(overwrite_policy=overwrite)
        )
    assert (output / "a" / "b").read_bytes() == b"b"


@pytest.mark.parametrize(
    ("on_disk", "member", "overwrite"),
    [
        ("directory", "file", zipctl.OverwritePolicy.REPLACE),
        ("directory", "symlink", zipctl.OverwritePolicy.REPLACE),
        ("file", "directory", zipctl.OverwritePolicy.REPLACE),
        ("file", "directory", zipctl.OverwritePolicy.RENAME),
        pytest.param(
            "symlink",
            "directory",
            zipctl.OverwritePolicy.REPLACE,
            marks=pytest.mark.skipif(os.name != "posix", reason="needs symlinks"),
        ),
    ],
)
def test_an_overwrite_writing_cannot_do_is_refused_before_writing(
    tmp_path: Path, on_disk: str, member: str, overwrite: zipctl.OverwritePolicy
) -> None:
    # REPLACE keeps a directory, and a directory member never replaces a file
    # nor is renamed: writing would fail after "z.txt".
    output = tmp_path / "out"
    output.mkdir()
    if on_disk == "directory":
        (output / "a").mkdir()
    elif on_disk == "symlink":
        (output / "a").symlink_to("x")
    else:
        (output / "a").write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("z.txt", b"z")
        if member == "directory":
            zf.mkdir("a")
        else:
            zf.writestr(_symlink("a") if member == "symlink" else "a", b"z.txt")
    policy = zipctl.ExtractPolicy(overwrite_policy=overwrite, allow_symlinks=True)

    with zipctl.ZipFile(buffer) as zf:
        found = [(v.member, v.code) for v in zf.assess(output, policy).violations]
        with pytest.raises(ExtractionError):
            zf.safe_extractall(output, policy=policy)
    assert found == [("a/" if member == "directory" else "a", "overwrite")]
    assert not (output / "z.txt").exists()


def test_a_skipped_symlink_on_a_directory_on_disk_is_no_overwrite(
    tmp_path: Path,
) -> None:
    output = tmp_path / "out"
    (output / "a").mkdir(parents=True)
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr(_symlink("a"), b"z.txt")
    policy = zipctl.ExtractPolicy(
        overwrite_policy=zipctl.OverwritePolicy.REPLACE,
        allow_symlinks=zipctl.ExtractPolicyRule(
            False, on_violation=zipctl.ViolationAction.SKIP
        ),
    )

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(output, policy=policy)
    assert result.members[0].status == zipctl.MemberStatus.SKIPPED
    assert (output / "a").is_dir()


def test_disk_parents_are_looked_up_by_their_exact_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A case-sensitive filesystem holding the directory "A" and the symlink "a":
    # a lookup keyed by the case-folded name would take "a" for the directory.
    output = tmp_path / "out"
    types = {
        os.fspath(output / "A"): stat.S_IFDIR,
        os.fspath(output / "a"): stat.S_IFLNK,
    }

    def file_type(path: Path) -> int:
        return types.get(os.fspath(path), 0)

    monkeypatch.setattr(validators, "_file_type", file_type)
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("A/x", b"x")
        zf.writestr("a/y", b"y")

    with zipctl.ZipFile(buffer) as zf:
        found = [(v.member, v.code) for v in zf.assess(output).violations]
    assert found == [("a/y", "symlink_parent")]


@pytest.mark.parametrize(
    ("name", "code"),
    [("n" * 60_000, "max_path_length"), ("d/" * 70 + "f", "max_path_depth")],
    ids=["long", "deep"],
)
def test_overlong_or_deep_paths_are_refused_before_writing(
    tmp_path: Path, name: str, code: str
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("ok.txt", b"ok")
        zf.writestr(name, b"x")
    output = tmp_path / "out"

    with zipctl.ZipFile(buffer) as zf, pytest.raises(ExtractionError) as caught:
        zf.safe_extractall(output)

    assert code in [v.code for v in caught.value.result.violations]
    assert not output.exists() or not any(output.iterdir())


def test_path_limits_can_be_lifted(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("d/" * 70 + "f", b"x")

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(
            tmp_path, policy=zipctl.ExtractPolicy(max_path_depth=None)
        )

    assert result.extracted_count == 1


def test_path_depth_counts_from_the_destination_not_its_root(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("d/f", b"x")
    policy = zipctl.ExtractPolicy(destination_root=tmp_path, max_path_depth=2)

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(tmp_path / "a" / "b" / "c", policy=policy)

    assert result.extracted_count == 1


def test_rename_resumes_from_the_last_suffix_of_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "rename.zip"
    output = tmp_path / "out"
    output.mkdir()
    (output / "a.txt").write_bytes(b"old")
    (output / "a.1.txt").write_bytes(b"old 1")
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", b"x")
        zf.writestr("./a.txt", b"y")
    attempts: list[str] = []
    real_link = os.link

    def counting_link(
        src: str,
        dst: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        attempts.append(os.path.basename(dst))
        real_link(
            src,
            dst,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    # Publishing checks os.link is in supports_dir_fd before using it.
    supported = {f for f in os.supports_dir_fd if f is not real_link}
    monkeypatch.setattr(os, "link", counting_link)
    monkeypatch.setattr(os, "supports_dir_fd", supported | {counting_link})
    with zipctl.ZipFile(archive) as zf:
        zf.safe_extractall(
            output,
            policy=zipctl.ExtractPolicy(
                overwrite_policy=zipctl.OverwritePolicy.RENAME,
                reject_duplicate_targets=False,
            ),
        )

    # the second member starts at a.3.txt instead of trying a.txt again
    assert attempts == ["a.txt", "a.1.txt", "a.2.txt", "a.3.txt"]
    assert (output / "a.3.txt").read_bytes() == b"y"


def _refuse_renamed(_info: ZipInfo, target: Path) -> None:
    if target.name != "a.txt":
        raise ValueError("no renamed files")


@pytest.mark.filterwarnings("ignore::UserWarning")
@pytest.mark.parametrize(
    ("names", "policy", "codes"),
    [
        (
            ["a.txt", "b.txt"],
            zipctl.ExtractPolicy(
                max_entries=1,
                on_violation=zipctl.ViolationAction.WARN,
                overwrite_policy=zipctl.OverwritePolicy.RENAME,
                custom_validator=_refuse_renamed,
            ),
            ["max_entries", "custom_validator", "custom_validator"],
        ),
        (
            ["a.txt", "b.txt"],
            zipctl.ExtractPolicy(
                on_violation=zipctl.ViolationAction.SKIP,
                overwrite_policy=zipctl.OverwritePolicy.RENAME,
                custom_validator=_refuse_renamed,
            ),
            ["custom_validator", "custom_validator"],
        ),
        (
            ["b.txt", "./b.txt"],
            zipctl.ExtractPolicy(
                overwrite_policy=zipctl.OverwritePolicy.ERROR,
                reject_duplicate_targets=False,
            ),
            ["overwrite"],
        ),
        (
            ["../x.txt", "b.txt", "c.txt"],
            zipctl.ExtractPolicy(
                max_entries=zipctl.ExtractPolicyRule(
                    2, on_violation=zipctl.ViolationAction.SKIP
                )
            ),
            ["max_entries", "parent_traversal", "archive_refused"],
        ),
    ],
)
def test_run_violations_are_the_archive_findings_then_every_members(
    tmp_path: Path, names: list[str], policy: zipctl.ExtractPolicy, codes: list[str]
) -> None:
    (tmp_path / "a.txt").write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        for name in names:
            zf.writestr(name, b"new")

    with zipctl.ZipFile(buffer) as zf:
        try:
            result = zf.safe_extractall(tmp_path, policy=policy)
        except ExtractionError as error:
            result = error.result

    archive = tuple(v for v in result.violations if v.code == "max_entries")
    members = tuple(v for m in result.members for v in m.violations)
    assert result.violations == archive + members
    assert [v.code for v in result.violations] == codes


@pytest.mark.parametrize(
    ("action", "status"),
    [
        (zipctl.ViolationAction.ERROR, zipctl.MemberStatus.FAILED),
        (zipctl.ViolationAction.SKIP, zipctl.MemberStatus.SKIPPED),
    ],
)
def test_a_rejected_rename_candidate_leaves_no_temporary_file(
    tmp_path: Path, action: zipctl.ViolationAction, status: zipctl.MemberStatus
) -> None:
    (tmp_path / "a.txt").write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"new")
    policy = zipctl.ExtractPolicy(
        overwrite_policy=zipctl.OverwritePolicy.RENAME,
        custom_validator=_refuse_renamed,
        on_violation=action,
    )

    with zipctl.ZipFile(buffer) as zf:
        try:
            result = zf.safe_extractall(tmp_path, policy=policy)
        except ExtractionError as error:
            result = error.result

    member = result.members[0]
    assert member.status == status
    assert member.target == tmp_path / "a.1.txt"
    assert member.bytes_written == 0
    assert [v.code for v in member.violations] == ["custom_validator"]
    assert result.violations == member.violations
    assert [p.name for p in tmp_path.iterdir()] == ["a.txt"]
    assert (tmp_path / "a.txt").read_bytes() == b"old"


def test_a_renamed_target_that_only_warns_is_used(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"new")
    policy = zipctl.ExtractPolicy(
        overwrite_policy=zipctl.OverwritePolicy.RENAME,
        custom_validator=_refuse_renamed,
        on_violation=zipctl.ViolationAction.WARN,
    )

    with zipctl.ZipFile(buffer) as zf, pytest.warns(UserWarning, match="renamed"):
        result = zf.safe_extractall(tmp_path, policy=policy)

    assert result.members[0].target == tmp_path / "a.1.txt"
    assert [v.code for v in result.violations] == ["custom_validator"]
    assert (tmp_path / "a.1.txt").read_bytes() == b"new"


def test_only_the_used_rename_candidate_warns(tmp_path: Path) -> None:
    for name in ("a.txt", "a.1.txt", "a.2.txt"):
        (tmp_path / name).write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"new")
    policy = zipctl.ExtractPolicy(
        overwrite_policy=zipctl.OverwritePolicy.RENAME,
        custom_validator=_refuse_renamed,
        on_violation=zipctl.ViolationAction.WARN,
    )

    with (
        zipctl.ZipFile(buffer) as zf,
        pytest.warns(UserWarning, match="renamed") as caught,
    ):
        result = zf.safe_extractall(tmp_path, policy=policy)

    member = result.members[0]
    assert member.target == tmp_path / "a.3.txt"
    assert [v.target for v in member.violations] == [tmp_path / "a.3.txt"]
    assert result.violations == member.violations
    assert len(caught) == 1


def test_a_renamed_target_is_held_to_the_path_length_limit(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"new")
    policy = zipctl.ExtractPolicy(
        overwrite_policy=zipctl.OverwritePolicy.RENAME,
        max_path_length=len(os.fsencode(tmp_path / "a.txt")),
    )

    with zipctl.ZipFile(buffer) as zf, pytest.raises(ExtractionError) as caught:
        zf.safe_extractall(tmp_path, policy=policy)

    member = caught.value.result.members[0]
    assert member.status == zipctl.MemberStatus.FAILED
    assert [v.code for v in member.violations] == ["max_path_length"]
    assert not (tmp_path / "a.1.txt").exists()


def test_each_target_keeps_its_own_rename_numbering(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"old a")
    (tmp_path / "b.txt").write_bytes(b"old b")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"a")
        zf.writestr("b.txt", b"b")

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(
            tmp_path,
            policy=zipctl.ExtractPolicy(overwrite_policy=zipctl.OverwritePolicy.RENAME),
        )

    assert [m.target for m in result.members] == [
        tmp_path / "a.1.txt",
        tmp_path / "b.1.txt",
    ]
    assert [m.bytes_written for m in result.members] == [1, 1]


def test_a_renamed_target_leaves_the_names_other_members_need(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.txt").write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"a")
        zf.writestr("A.1.txt", b"a.1")

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(
            tmp_path,
            policy=zipctl.ExtractPolicy(overwrite_policy=zipctl.OverwritePolicy.RENAME),
        )

    assert [m.target for m in result.members] == [
        tmp_path / "a.2.txt",
        tmp_path / "A.1.txt",
    ]


def test_a_renamed_target_leaves_the_directories_other_members_need(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.txt").write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"a")
        zf.writestr("a.1.txt/b", b"b")

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(
            tmp_path,
            policy=zipctl.ExtractPolicy(overwrite_policy=zipctl.OverwritePolicy.RENAME),
        )

    assert [m.target for m in result.members] == [
        tmp_path / "a.2.txt",
        tmp_path / "a.1.txt" / "b",
    ]


# Why each rule left out of TARGET_NAME_VALIDATORS cannot change on rename:
# a candidate keeps the member, its parent directory and its name up to the
# first dot.
RULES_A_RENAME_CANNOT_CHANGE: dict[validators.MemberValidator, str] = {
    validators.check_supported: "reads the member's method and flags",
    validators.check_absolute_path: "reads the member name",
    validators.check_windows_drive_and_unc: "reads the member name",
    validators.check_parent_traversal: "reads the member name",
    validators.check_outside_root: "the parent stays the same",
    validators.check_duplicate_target: "the run skips every member's target",
    validators.check_overwrite_conflict: "RENAME is the policy that resolves it",
    validators.check_max_member_size: "reads the member's size",
    validators.check_compression_ratio: "reads the member's sizes",
    validators.check_symlink_allowed: "reads the member's type",
    validators.check_parents: "the parent stays the same; RENAME clears the rest",
    validators.check_special_file_allowed: "reads the member's type",
    validators.check_utf8_name: "reads the member name",
    validators.check_total_uncompressed_size: "reads the member's size",
}


def test_every_extract_rule_is_checked_again_on_rename_or_cannot_change() -> None:
    renamed = set(validators.TARGET_NAME_VALIDATORS)
    assert set(validators.EXTRACT_VALIDATORS) == (
        renamed | RULES_A_RENAME_CANNOT_CHANGE.keys()
    )
    assert not renamed & RULES_A_RENAME_CANNOT_CHANGE.keys()


@pytest.mark.parametrize(
    ("name", "renamed"),
    [
        ("file.tar.gz", "file.1.tar.gz"),
        ("README", "README.1"),
        (".bashrc", ".bashrc.1"),
        pytest.param(
            "notes.",
            "notes..1",
            marks=pytest.mark.skipif(os.name == "nt", reason="Windows drops it"),
        ),
    ],
)
def test_rename_counts_before_the_whole_extension(
    tmp_path: Path, name: str, renamed: str
) -> None:
    (tmp_path / name).write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr(name, b"new")

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(
            tmp_path,
            policy=zipctl.ExtractPolicy(overwrite_policy=zipctl.OverwritePolicy.RENAME),
        )

    assert [m.target for m in result.members] == [tmp_path / renamed]


def test_a_renamed_target_keeps_an_allowed_compound_extension(tmp_path: Path) -> None:
    (tmp_path / "file.tar.gz").write_bytes(b"old")
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("file.tar.gz", b"new")

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(
            tmp_path,
            policy=zipctl.ExtractPolicy(
                overwrite_policy=zipctl.OverwritePolicy.RENAME,
                allowed_extensions=frozenset({".tar.gz"}),
            ),
        )

    assert [(m.status, m.target) for m in result.members] == [
        (zipctl.MemberStatus.EXTRACTED, tmp_path / "file.1.tar.gz")
    ]


def test_directory_members_report_their_target(tmp_path: Path) -> None:
    (tmp_path / "old").mkdir()
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("./", b"")
        zf.writestr("old/", b"")
        zf.writestr("new/", b"")

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(
            tmp_path,
            policy=zipctl.ExtractPolicy(overwrite_policy=zipctl.OverwritePolicy.RENAME),
        )

    assert [(m.status, m.target, m.overwritten) for m in result.members] == [
        (zipctl.MemberStatus.EXTRACTED, tmp_path, False),
        (zipctl.MemberStatus.EXTRACTED, tmp_path / "old", True),
        (zipctl.MemberStatus.EXTRACTED, tmp_path / "new", False),
    ]
    assert result.violations == ()


@pytest.mark.parametrize(
    ("overwrite", "status"),
    [
        (zipctl.OverwritePolicy.ERROR, zipctl.MemberStatus.FAILED),
        (zipctl.OverwritePolicy.SKIP, zipctl.MemberStatus.SKIPPED),
    ],
)
def test_exclusive_policies_never_rename_a_duplicate_target(
    tmp_path: Path, overwrite: zipctl.OverwritePolicy, status: zipctl.MemberStatus
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"x")
        zf.writestr("./a.txt", b"y")
    policy = zipctl.ExtractPolicy(
        overwrite_policy=overwrite, reject_duplicate_targets=False
    )
    with zipctl.ZipFile(buffer) as zf:
        try:
            result = zf.safe_extractall(tmp_path, policy=policy)
        except ExtractionError as error:
            result = error.result

    assert [p.name for p in tmp_path.iterdir()] == ["a.txt"]
    assert (tmp_path / "a.txt").read_bytes() == b"x"
    assert result.members[1].status == status
    assert [v.code for v in result.members[1].violations] == ["overwrite"]


def test_path_limits_refuse_even_when_violations_only_warn(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("n" * 60_000, b"x")

    with zipctl.ZipFile(buffer) as zf, pytest.raises(ExtractionError):
        zf.safe_extractall(
            tmp_path / "out",
            policy=zipctl.ExtractPolicy(on_violation=zipctl.ViolationAction.WARN),
        )


@pytest.mark.skipif(os.name != "posix", reason="needs symlinks")
def test_a_skipped_symlink_does_not_block_paths_below_its_name(
    tmp_path: Path,
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        link = ZipInfo("l")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, b"elsewhere")
        zf.writestr("l/x", b"x")
    output = tmp_path / "out"

    with zipctl.ZipFile(buffer) as zf:
        result = zf.safe_extractall(
            output,
            policy=zipctl.ExtractPolicy(on_violation=zipctl.ViolationAction.SKIP),
        )

    assert [m.status.value for m in result.members] == ["skipped", "extracted"]
    assert (output / "l" / "x").read_bytes() == b"x"


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("C:evil.txt", "windows_drive_path"),
        ("C:/evil.txt", "windows_drive_path"),
        ("//server/share/evil.txt", "windows_path"),
        ("\\\\server\\share\\evil.txt", "windows_path"),
    ],
)
def test_windows_drive_and_unc_names_get_one_matching_violation(
    tmp_path: Path, name: str, code: str
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr(name, b"x")
    with (
        zipctl.ZipFile(buffer) as zf,
        pytest.raises(zipctl.ExtractionError) as excinfo,
    ):
        zf.safe_extractall(tmp_path / "out")
    codes = [v.code for v in excinfo.value.result.violations]
    assert code in codes
    assert {"windows_drive_path", "windows_path"} & set(codes) == {code}


@pytest.mark.skipif(os.name != "posix", reason="needs symlinks and dir_fd")
def test_an_entry_kind_without_dir_fd_support_is_refused_not_made_by_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        info = ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "target")
    # a path-based fallback would reopen the race the descriptor closes
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd - {os.symlink})
    with (
        zipctl.ZipFile(buffer) as zf,
        pytest.raises(zipctl.ExtractionError) as excinfo,
    ):
        zf.safe_extractall(tmp_path, policy=zipctl.ExtractPolicy(allow_symlinks=True))
    messages = [v.message for v in excinfo.value.result.violations]
    assert any("relative to a directory descriptor" in m for m in messages), messages
    assert not os.path.lexists(tmp_path / "link")


@pytest.mark.skipif(os.name != "posix", reason="needs symlinks")
def test_a_symlink_that_appears_where_a_directory_is_made_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.mkdir("dir")
        zf.writestr("dir/file.txt", b"payload")
    outside = tmp_path / "outside"
    outside.mkdir()
    real_mkdir = os.mkdir

    def racing_mkdir(
        path: str, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> None:
        if os.path.basename(path) == "dir":  # an attacker wins the race
            os.symlink(outside, path, dir_fd=dir_fd)
        real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", racing_mkdir)
    with (
        zipctl.ZipFile(buffer) as zf,
        pytest.raises(zipctl.ExtractionError) as excinfo,
    ):
        zf.safe_extractall(tmp_path / "out")
    assert excinfo.value.result.extracted_count == 0
    assert list(outside.iterdir()) == []


def _symlink_archive(target: str) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("new", b"x")
        info = ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, target)
    return buffer


@pytest.mark.skipif(os.name != "posix", reason="needs symlinks")
@pytest.mark.parametrize(
    ("overwrite", "expected"),
    [("rename", {"link": "old", "link.1": "new"}), ("replace", {"link": "new"})],
)
def test_an_archive_symlink_over_an_existing_symlink_never_follows_it(
    tmp_path: Path, overwrite: str, expected: dict[str, str]
) -> None:
    (tmp_path / "old").write_bytes(b"old")
    (tmp_path / "link").symlink_to("old")
    with zipctl.ZipFile(_symlink_archive("new")) as zf:
        zf.safe_extractall(
            tmp_path,
            policy=zipctl.ExtractPolicy(
                allow_symlinks=True, overwrite_policy=zipctl.OverwritePolicy(overwrite)
            ),
        )
    links = {p.name: os.readlink(p) for p in tmp_path.iterdir() if p.is_symlink()}
    assert links == expected
    assert (tmp_path / "old").read_bytes() == b"old"


@pytest.mark.skipif(os.name != "posix", reason="needs symlinks")
@pytest.mark.parametrize("overwrite", ["rename", "replace"])
def test_an_existing_symlink_out_of_the_destination_is_never_written_through(
    tmp_path: Path, overwrite: str
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    secret = tmp_path / "secret"
    secret.write_bytes(b"orig")
    (out / "link").symlink_to(secret)
    with (
        zipctl.ZipFile(_symlink_archive("new")) as zf,
        pytest.raises(zipctl.ExtractionError) as excinfo,
    ):
        zf.safe_extractall(
            out,
            policy=zipctl.ExtractPolicy(
                allow_symlinks=True, overwrite_policy=zipctl.OverwritePolicy(overwrite)
            ),
        )
    assert excinfo.value.result.extracted_count == 0
    assert os.readlink(out / "link") == str(secret)
    assert secret.read_bytes() == b"orig"
