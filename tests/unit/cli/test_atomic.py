"""Writing through a scratch file that is only moved into place on success."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ziplet.cli.atomic import replacing
from ziplet.cli.errors import CliError


def leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.startswith(".ziplet-"))


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


@pytest.mark.parametrize("error", [RuntimeError("boom"), KeyboardInterrupt()])
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
