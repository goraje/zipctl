"""Writing through a scratch file that is only moved into place on success."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

import pytest

from zipctl.cli.atomic import replacing
from zipctl.cli.errors import CliError


def leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.startswith(".zipctl-"))


def test_success_moves_the_scratch_file_onto_the_target(tmp_path: Path) -> None:
    target = tmp_path / "out.zip"
    with replacing(str(target), overwrite=False) as scratch:
        assert os.path.dirname(scratch) == str(tmp_path)
        Path(scratch).write_bytes(b"done")
    assert target.read_bytes() == b"done"
    assert leftovers(tmp_path) == []


def test_an_existing_target_is_refused_up_front_unless_overwriting(
    tmp_path: Path,
) -> None:
    target = tmp_path / "out.zip"
    target.write_bytes(b"old")
    with (
        pytest.raises(CliError, match="already exists"),
        replacing(str(target), overwrite=False),
    ):
        pytest.fail("the block must not run")
    assert target.read_bytes() == b"old"


def test_a_target_that_appears_during_the_block_is_not_replaced(
    tmp_path: Path,
) -> None:
    target = tmp_path / "out.zip"
    with pytest.raises(CliError, match="already exists"):  # noqa: PT012
        with replacing(str(target), overwrite=False) as scratch:
            Path(scratch).write_bytes(b"mine")
            target.write_bytes(b"theirs")
    assert target.read_bytes() == b"theirs"
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize(
    "error", [RuntimeError("boom"), KeyboardInterrupt(), SystemExit()]
)
def test_a_failing_block_leaves_the_target_untouched_and_no_scratch(
    tmp_path: Path, error: BaseException
) -> None:
    target = tmp_path / "out.zip"
    target.write_bytes(b"old")
    with pytest.raises(type(error)):  # noqa: PT012
        with replacing(str(target), overwrite=True) as scratch:
            Path(scratch).write_bytes(b"half")
            raise error
    assert target.read_bytes() == b"old"
    assert leftovers(tmp_path) == []


def test_seed_starts_the_scratch_file_as_a_copy_of_the_target(tmp_path: Path) -> None:
    target = tmp_path / "out.zip"
    target.write_bytes(b"first")
    with replacing(str(target), overwrite=True, seed=True) as scratch:
        assert Path(scratch).read_bytes() == b"first"
        Path(scratch).write_bytes(b"first+second")
    assert target.read_bytes() == b"first+second"


def test_a_symlinked_target_keeps_its_link(tmp_path: Path) -> None:
    real = tmp_path / "real.zip"
    real.write_bytes(b"old")
    link = tmp_path / "link.zip"
    link.symlink_to(real)
    with replacing(str(link), overwrite=True) as scratch:
        Path(scratch).write_bytes(b"new")
    assert link.is_symlink()
    assert real.read_bytes() == b"new"


def test_an_unwritable_directory_is_a_cli_error(tmp_path: Path) -> None:
    with (
        pytest.raises(CliError, match="cannot create"),
        replacing(str(tmp_path / "missing" / "out.zip"), overwrite=False),
    ):
        pytest.fail("the block must not run")


@pytest.mark.skipif(
    os.name != "posix" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions, which root ignores",
)
def test_a_directory_that_cannot_be_searched_is_a_cli_error(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o600)  # nothing in it can be created, or removed
    try:
        with (
            pytest.raises(CliError, match="cannot create"),
            replacing(str(locked / "out.zip"), overwrite=False),
        ):
            pytest.fail("the block must not run")
    finally:
        locked.chmod(0o700)


def test_an_interrupt_while_creating_the_scratch_file_leaves_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "chmod", interrupted)
    with (
        pytest.raises(KeyboardInterrupt),
        replacing(str(tmp_path / "out.zip"), overwrite=False),
    ):
        pytest.fail("the block must not run")
    assert leftovers(tmp_path) == []


def test_seeding_a_missing_target_starts_empty(tmp_path: Path) -> None:
    target = tmp_path / "out.zip"
    with replacing(str(target), overwrite=True, seed=True) as scratch:
        assert Path(scratch).read_bytes() == b""


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX permissions")
def test_new_files_get_ordinary_permissions_and_seeded_ones_keep_theirs(
    tmp_path: Path,
) -> None:
    mask = os.umask(0o022)
    try:
        fresh = tmp_path / "fresh.zip"
        with replacing(str(fresh), overwrite=False):
            pass
        assert stat.S_IMODE(fresh.stat().st_mode) == 0o644
    finally:
        os.umask(mask)
    kept = tmp_path / "kept.zip"
    kept.write_bytes(b"x")
    kept.chmod(0o600)
    with replacing(str(kept), overwrite=True, seed=True):
        pass
    assert stat.S_IMODE(kept.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX permissions")
def test_overwriting_keeps_the_permissions_of_the_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "secret.zip"
    target.write_bytes(b"old")
    target.chmod(0o600)
    with replacing(str(target), overwrite=True) as scratch:
        Path(scratch).write_bytes(b"new")
    assert target.read_bytes() == b"new"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX permissions")
def test_a_new_file_follows_the_umask_without_changing_it(tmp_path: Path) -> None:
    mask = os.umask(0o077)
    try:
        with replacing(str(tmp_path / "fresh.zip"), overwrite=False):
            pass
        assert os.umask(mask) == 0o077
    finally:
        os.umask(mask)
    assert stat.S_IMODE((tmp_path / "fresh.zip").stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX directories")
def test_the_directory_is_synced_after_the_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[bool] = []
    real = os.fsync

    def fsync(fd: int) -> None:
        synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    with replacing(str(tmp_path / "out.zip"), overwrite=False):
        pass
    assert synced == [False, True]  # the file, then its directory


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX directories")
def test_a_directory_that_cannot_be_synced_is_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = os.fsync

    def fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("not supported")
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    with replacing(str(tmp_path / "out.zip"), overwrite=False) as scratch:
        Path(scratch).write_bytes(b"done")
    assert (tmp_path / "out.zip").read_bytes() == b"done"


def _no_hard_links(*_args: object, **_kwargs: object) -> None:
    raise PermissionError(1, "Operation not permitted")


def test_filesystem_without_hard_links_still_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "link", _no_hard_links)
    target = tmp_path / "out.zip"
    with replacing(str(target), overwrite=False) as scratch:
        Path(scratch).write_bytes(b"done")
    assert target.read_bytes() == b"done"
    assert leftovers(tmp_path) == []


def test_filesystem_without_hard_links_never_clobbers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "link", _no_hard_links)
    target = tmp_path / "out.zip"

    def publish_while_another_file_appears() -> None:
        with replacing(str(target), overwrite=False) as scratch:
            Path(scratch).write_bytes(b"new")
            target.write_bytes(b"raced")  # appears after the up-front check

    with pytest.raises(CliError, match="already exists"):
        publish_while_another_file_appears()
    assert target.read_bytes() == b"raced"
    assert leftovers(tmp_path) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_a_read_only_target_can_be_replaced(tmp_path: Path) -> None:
    target = tmp_path / "out.zip"
    target.write_bytes(b"old")
    target.chmod(0o444)
    with replacing(str(target), overwrite=True) as scratch:
        Path(scratch).write_bytes(b"new")
    assert target.read_bytes() == b"new"
    assert stat.S_IMODE(target.stat().st_mode) == 0o444


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_a_new_output_is_never_more_permissive_than_its_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "secret.zip"
    source.write_bytes(b"x")
    source.chmod(0o600)
    target = tmp_path / "plain.zip"
    with replacing(str(target), overwrite=False, mode_from=str(source)) as scratch:
        Path(scratch).write_bytes(b"y")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_the_scratch_file_is_private_while_written(tmp_path: Path) -> None:
    previous = os.umask(0o022)
    try:
        with replacing(str(tmp_path / "out.zip"), overwrite=False) as scratch:
            assert stat.S_IMODE(os.stat(scratch).st_mode) == 0o600
    finally:
        os.umask(previous)
    assert stat.S_IMODE(os.stat(tmp_path / "out.zip").st_mode) == 0o644


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership")
def test_a_symlink_planted_by_another_user_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim = tmp_path / "victim"
    link = tmp_path / "out.zip"
    link.symlink_to(victim)
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
    with (
        pytest.raises(CliError, match="owned by another user"),
        replacing(str(link), overwrite=True),
    ):
        pytest.fail("the block must not run")
    assert not victim.exists()


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX permissions")
def test_a_new_file_copied_from_a_source_follows_the_umask(tmp_path: Path) -> None:
    source = tmp_path / "source.zip"
    source.write_bytes(b"")
    source.chmod(0o644)
    mask = os.umask(0o077)
    try:
        with replacing(
            str(tmp_path / "fresh.zip"), overwrite=False, mode_from=str(source)
        ):
            pass
    finally:
        os.umask(mask)
    assert stat.S_IMODE((tmp_path / "fresh.zip").stat().st_mode) == 0o600


def test_a_scratch_name_already_taken_is_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def taken(_nbytes: int | None = None) -> str:
        return "taken"

    monkeypatch.setattr(secrets, "token_hex", taken)
    planted = tmp_path / ".zipctl-taken.tmp"
    planted.write_bytes(b"not ours")
    with (
        pytest.raises(CliError, match="cannot create"),
        replacing(str(tmp_path / "out.zip"), overwrite=False),
    ):
        pytest.fail("the block must not run")
    assert planted.read_bytes() == b"not ours"
