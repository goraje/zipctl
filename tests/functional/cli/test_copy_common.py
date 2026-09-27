"""What ``encrypt``, ``decrypt`` and ``rewrite`` share: safety, fidelity, output."""

from __future__ import annotations

import os
import random
import warnings
from pathlib import Path
from typing import cast

import pytest

import zipctl
from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.reports import CopyReport, load_json
from tests.functional.cli.rewrite_support import (
    FILES,
    PASSWORD,
    PW,
    leftovers,
    make_source,
    snapshot,
)
from tests.functional.cli.support import Result, data_offset, flip_byte, write_archive
from zipctl import ZipFile

AES256 = zipctl.ZipFileExtra(wz_aes_nbits=256)


def write_for(
    command: str,
    path: Path,
    members: list[tuple[str, bytes]],
    compression: int = zipctl.ZIP_STORED,
) -> Path:
    """An archive fit for *command*: plain for encrypt, AES-256 for the others."""
    if command == "encrypt":
        return write_archive(path, members, compression=compression)
    return write_archive(
        path,
        members,
        encryption=zipctl.WZ_AES,
        password=PW,
        extra=AES256,
        compression=compression,
    )


@pytest.fixture(params=["encrypt", "decrypt", "rewrite"])
def job(request: pytest.FixtureRequest, workdir: Path) -> tuple[str, Path, list[str]]:
    """(command, source archive, options that make the command succeed)."""
    pw = workdir / "pw"
    pw.write_text(PASSWORD + "\n")
    name = cast("str", request.param)
    if name == "encrypt":
        source = make_source(workdir / "in.zip")
        return name, source, ["--password-file", str(pw)]
    source = make_source(
        workdir / "in.zip", encryption=zipctl.WZ_AES, password=PW, extra=AES256
    )
    if name == "decrypt":
        return name, source, ["--password-file", str(pw)]
    return name, source, ["--old-password-file", str(pw), "--compression", "store"]


def go(
    cli: CliRunner, job: tuple[str, Path, list[str]], out: Path, *more: str
) -> Result:
    name, source, options = job
    return cli(name, str(source), str(out), *options, *more)


# --- never in place ---------------------------------------------------------------


def test_the_output_may_not_be_the_input(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    source = job[1]
    before = source.read_bytes()
    for force in ([], ["--force"]):
        result = go(cli, job, source, *force)
        assert result.returncode == 2, result
        assert "in place" in result.stderr
    assert source.read_bytes() == before
    assert leftovers(workdir) == []


def test_the_output_may_not_be_the_input_by_another_name(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    source = job[1]
    before = source.read_bytes()
    (workdir / "sub").mkdir()
    for alias in (workdir / "sub" / ".." / "in.zip", workdir / "./in.zip"):
        result = go(cli, job, alias, "--force")
        assert result.returncode == 2, result
    if hasattr(os, "symlink"):
        (workdir / "alias.zip").symlink_to(source)
        result = go(cli, job, workdir / "alias.zip", "--force")
        assert result.returncode == 2, result
        assert (workdir / "alias.zip").is_symlink()
    assert source.read_bytes() == before
    assert leftovers(workdir) == []


# --- an existing output ---------------------------------------------------------------


def test_an_existing_output_is_refused_without_force(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    out = workdir / "out.zip"
    out.write_bytes(b"precious")
    result = go(cli, job, out)
    assert result.returncode == 1, result
    assert "already exists" in result.stderr
    assert "--force" in result.stderr
    assert out.read_bytes() == b"precious"
    assert leftovers(workdir) == []


def test_force_replaces_an_existing_output(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    out = workdir / "out.zip"
    out.write_bytes(b"precious")
    result = go(cli, job, out, "--force")
    assert result.returncode == 0, result
    with ZipFile(out) as zf:
        assert zf.namelist()
    assert leftovers(workdir) == []


def test_the_refusal_comes_before_any_password_is_asked_for(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    name, source, _ = job
    out = workdir / "out.zip"
    out.write_bytes(b"precious")
    result = cli(name, str(source), str(out))  # no password options at all
    assert result.returncode == 1, result
    assert "already exists" in result.stderr


# --- bad input --------------------------------------------------------------------


def test_a_missing_input_is_an_error(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    name, _, options = job
    result = cli(name, str(workdir / "missing.zip"), str(workdir / "out.zip"), *options)
    assert result.returncode == 1, result
    assert "cannot open" in result.stderr
    assert not (workdir / "out.zip").exists()


def test_a_file_that_is_not_a_zip_is_an_error(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    name, _, options = job
    (workdir / "junk.zip").write_bytes(b"this is not a zip file" * 10)
    result = cli(name, str(workdir / "junk.zip"), str(workdir / "out.zip"), *options)
    assert result.returncode == 1, result
    assert "not a valid ZIP" in result.stderr
    assert not (workdir / "out.zip").exists()


def test_a_missing_output_directory_is_an_error(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    result = go(cli, job, workdir / "nope" / "out.zip")
    assert result.returncode == 1, result
    assert "cannot create" in result.stderr


def test_a_damaged_member_fails_the_run_and_leaves_nothing(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    name, source, options = job
    flip_byte(source, data_offset(source, "docs/data.bin") + 20)
    out = workdir / "out.zip"
    out.write_bytes(b"precious")
    result = cli(name, str(source), str(out), *options, "--force")
    assert result.returncode == 1, result
    assert "docs/data.bin" in result.stderr
    assert out.read_bytes() == b"precious"
    assert leftovers(workdir) == []


# --- fidelity ---------------------------------------------------------------------


def test_everything_but_the_protection_is_preserved(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    name, source, _ = job
    out = workdir / "out.zip"
    result = go(cli, job, out)
    assert result.returncode == 0, result
    before = snapshot(source, PW)
    after = snapshot(out, PW)
    assert list(after) == list(before)  # same members in the same order
    for member, row in before.items():
        date, mode, comment, method, is_dir, data, internal, system, extras = row
        new = after[member]
        assert new[0] == date, member
        assert new[1] == mode, member
        assert new[2] == comment, member
        assert new[4] == is_dir, member
        assert new[5] == data, member
        assert new[6] == internal, member
        assert new[7] == system, member
        assert extras, member  # the source has UT and ux fields
        assert new[8] == extras, member
        if name != "rewrite":  # rewrite in this fixture recompresses to store
            assert new[3] == method, member
    with ZipFile(source) as a, ZipFile(out) as b:
        assert b.comment == a.comment == b"the archive comment"
    assert leftovers(workdir) == []


def test_the_aes_field_is_written_once_among_the_kept_extras(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    name = job[0]
    out = workdir / "out.zip"
    assert go(cli, job, out).returncode == 0
    with ZipFile(out) as zf:
        for info in zf.infolist():
            if not info.is_dir():
                aes_fields = info.extra.count(b"\x01\x99\x07\x00")
                assert aes_fields == (name != "decrypt"), info.filename


def test_a_large_member_is_copied_intact(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    name, _, options = job
    rng = random.Random(5)
    big = rng.randbytes(3 * (1 << 20) + 17) + b"a" * 100000
    source = write_for(
        name,
        workdir / "big.zip",
        [("big.bin", big)],
        compression=zipctl.ZIP_DEFLATED,
    )
    result = cli(name, str(source), str(workdir / "out.zip"), *options)
    assert result.returncode == 0, result
    assert snapshot(workdir / "out.zip", PW)["big.bin"][5] == big


def test_members_with_duplicate_names_each_keep_their_data(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    name, _, options = job
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        source = write_for(
            name, workdir / "dup.zip", [("x.txt", b"first"), ("x.txt", b"second")]
        )
    out = workdir / "out.zip"
    result = cli(name, str(source), str(out), *options)
    assert result.returncode == 0, result
    with ZipFile(out) as zf:
        got = [zf.read(i, pwd=PW if i.is_encrypted else None) for i in zf.infolist()]
    assert got == [b"first", b"second"]


# --- reporting -----------------------------------------------------------------------


def test_the_summary_names_both_archives_and_says_it_was_verified(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    result = go(cli, job, workdir / "out.zip")
    line = result.stdout.strip()
    assert "in.zip" in line
    assert "out.zip" in line
    assert "6 files, 2 directories" in line
    assert line.endswith("(verified)")
    assert result.stderr == "" or "warning" in result.stderr


def test_quiet_prints_nothing(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    result = go(cli, job, workdir / "out.zip", "-q")
    assert result.returncode == 0, result
    assert (result.stdout, result.stderr) == ("", "")


def test_verbose_lists_every_member(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    result = go(cli, job, workdir / "out.zip", "-v")
    lines = result.stdout.splitlines()
    assert "Copying: docs/ (directory)" in lines
    for name, _, _ in FILES:
        assert any(line.startswith(f"Copying: {name} (") for line in lines), name
    assert lines[-2] == ""
    assert lines[-1].startswith(("Encrypted ", "Decrypted ", "Rewrote "))


def test_verbose_and_quiet_conflict(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    result = go(cli, job, workdir / "out.zip", "-v", "-q")
    assert result.returncode == 2, result
    assert not (workdir / "out.zip").exists()


def test_json_output_describes_the_copy(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    name, source, _ = job
    out = workdir / "out.zip"
    result = go(cli, job, out, "--json")
    assert result.returncode == 0, result
    doc = load_json(result, CopyReport)
    assert doc["ok"] is True
    assert doc["input"] == str(source)
    assert doc["output"] == str(out)
    assert doc["verified"] is True
    assert (doc["file_count"], doc["directory_count"]) == (6, 2)
    assert [m["name"] for m in doc["members"]][:2] == ["docs/", "notes/"]
    member = next(m for m in doc["members"] if m["name"] == "docs/readme.txt")
    assert member["size"] == len(FILES[0][2])
    expected = {
        "encrypt": ("none", "AES-256"),
        "decrypt": ("AES-256", "none"),
        "rewrite": ("AES-256", "AES-256"),
    }[name]
    assert (member["encryption_before"], member["encryption_after"]) == expected
    assert doc["encrypted_count"] == (0 if name == "decrypt" else 6)


def test_json_output_is_only_json_even_with_verbose(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    result = go(cli, job, workdir / "out.zip", "--json", "-v")
    assert result.returncode == 0, result
    load_json(result, CopyReport)


def test_no_verify_is_reported(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    result = go(cli, job, workdir / "out.zip", "--no-verify")
    assert result.returncode == 0, result
    assert "verified" not in result.stdout
    doc = load_json(
        go(cli, job, workdir / "o2.zip", "--no-verify", "--json"), CopyReport
    )
    assert doc["verified"] is False


def test_hostile_member_names_cannot_inject_terminal_escapes(
    cli: CliRunner, workdir: Path, job: tuple[str, Path, list[str]]
) -> None:
    name, _, options = job
    source = write_for(name, workdir / "evil.zip", [("bad\x1b[31mname\n.txt", b"x")])
    result = cli(name, str(source), str(workdir / "out.zip"), *options, "-v")
    assert result.returncode == 0, result
    assert "\x1b" not in result.stdout
    assert "\x1b" not in result.stderr
    assert "bad\\x1b[31mname\\x0a.txt" in result.stdout
