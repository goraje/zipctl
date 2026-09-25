"""``replacing``: a failed run leaves the target untouched and no scratch file."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from ziplet.cli.atomic import replacing
from ziplet.cli.errors import CliError


def scratch_files(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.startswith(".ziplet-"))


def test_success_moves_the_scratch_file_onto_the_target(tmp_path: Path) -> None:
    target = tmp_path / "out.zip"
    with replacing(str(target), overwrite=False) as scratch:
        assert os.path.dirname(scratch) == str(tmp_path)
        assert not target.exists()
        Path(scratch).write_bytes(b"done")
    assert target.read_bytes() == b"done"
    assert scratch_files(tmp_path) == []


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_any_failure_removes_the_scratch_file_and_keeps_the_target(
    tmp_path: Path, error: type[BaseException]
) -> None:
    target = tmp_path / "out.zip"
    target.write_bytes(b"original")

    def fail() -> None:
        with replacing(str(target), overwrite=True) as scratch:
            Path(scratch).write_bytes(b"half")
            raise error

    with pytest.raises(error):
        fail()
    assert target.read_bytes() == b"original"
    assert scratch_files(tmp_path) == []


def test_an_existing_target_is_refused_before_any_work(tmp_path: Path) -> None:
    target = tmp_path / "out.zip"
    target.write_bytes(b"original")
    entered = False
    with pytest.raises(CliError, match="already exists"):
        with replacing(str(target), overwrite=False):
            entered = True
    assert not entered
    assert scratch_files(tmp_path) == []


def test_a_target_created_meanwhile_is_not_clobbered(tmp_path: Path) -> None:
    target = tmp_path / "out.zip"

    def race() -> None:
        with replacing(str(target), overwrite=False) as scratch:
            Path(scratch).write_bytes(b"mine")
            target.write_bytes(b"someone else's")

    with pytest.raises(CliError, match="already exists"):
        race()
    assert target.read_bytes() == b"someone else's"
    assert scratch_files(tmp_path) == []


def test_seeding_starts_from_a_copy_of_the_target(tmp_path: Path) -> None:
    target = tmp_path / "out.zip"
    target.write_bytes(b"base")
    with replacing(str(target), overwrite=True, seed=True) as scratch:
        assert Path(scratch).read_bytes() == b"base"
        Path(scratch).write_bytes(b"base+more")
    assert target.read_bytes() == b"base+more"


def test_seeding_a_missing_target_starts_empty(tmp_path: Path) -> None:
    target = tmp_path / "out.zip"
    with replacing(str(target), overwrite=True, seed=True) as scratch:
        assert Path(scratch).read_bytes() == b""


def test_a_missing_directory_is_a_clean_error(tmp_path: Path) -> None:
    with pytest.raises(CliError, match="cannot create"):
        with replacing(str(tmp_path / "nope" / "out.zip"), overwrite=False):
            pass


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
