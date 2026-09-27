"""``ziplet encrypt``: an unencrypted archive in, an encrypted copy out."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest
from typing_extensions import Unpack

import ziplet
from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.rewrite_support import (
    FILES,
    PASSWORD,
    PW,
    leftovers,
    make_mixed,
    make_source,
    schemes,
    snapshot,
)
from tests.functional.cli.support import (
    END_OF_INPUT,
    HAS_PTY,
    Result,
    RunOptions,
    write_archive,
)
from tests.functional.cli.support import run_in_terminal as terminal
from ziplet import ZipFile

ENV = {"ZIPLET_PASSWORD": PASSWORD}
needs_pty = pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")
NAMES = [name for name, _, _ in FILES]


@pytest.fixture
def source(workdir: Path) -> Path:
    return make_source(workdir / "in.zip")


def encrypt(
    cli: CliRunner, workdir: Path, *args: str, **kw: Unpack[RunOptions]
) -> Result:
    return cli(
        "encrypt", str(workdir / "in.zip"), str(workdir / "out.zip"), *args, **kw
    )


def matches(cli: CliRunner, archive: Path, password: str) -> bool:
    result = cli(
        "check-password", "--full", str(archive), env={"ZIPLET_PASSWORD": password}
    )
    return result.returncode == 0


# --- methods ----------------------------------------------------------------------


@pytest.mark.parametrize("method", ["aes128", "aes192", "aes256", "zipcrypto"])
def test_every_file_gets_the_method(
    cli: CliRunner, workdir: Path, source: Path, method: str
) -> None:
    result = encrypt(cli, workdir, "--encryption", method, env=ENV)
    assert result.returncode == 0, result
    out = workdir / "out.zip"
    assert set(schemes(out).values()) == {method}
    assert snapshot(out, PW) == snapshot(source)
    assert matches(cli, out, PASSWORD)
    assert not matches(cli, out, "another password") or method == "zipcrypto"


@pytest.mark.usefixtures("source")
def test_the_default_method_is_aes256(cli: CliRunner, workdir: Path) -> None:
    encrypt(cli, workdir, env=ENV)
    assert set(schemes(workdir / "out.zip").values()) == {"aes256"}


def test_the_input_is_left_alone(cli: CliRunner, workdir: Path, source: Path) -> None:
    before = source.read_bytes()
    encrypt(cli, workdir, env=ENV)
    assert source.read_bytes() == before


@pytest.mark.usefixtures("source")
def test_aes_version_one_can_be_asked_for(cli: CliRunner, workdir: Path) -> None:
    result = encrypt(cli, workdir, "--wz-aes-version", "1", env=ENV)
    assert result.returncode == 0, result
    assert set(schemes(workdir / "out.zip").values()) == {"aes256-v1"}


@pytest.mark.usefixtures("source")
def test_aes_version_two_is_the_default(cli: CliRunner, workdir: Path) -> None:
    encrypt(cli, workdir, env=ENV)
    with ZipFile(workdir / "out.zip") as zf:
        versions = {i.aes_extra.wz_aes_version for i in zf.infolist() if i.is_encrypted}
    assert versions == {2}


@pytest.mark.usefixtures("source")
def test_an_aes_version_means_nothing_for_zipcrypto(
    cli: CliRunner, workdir: Path
) -> None:
    result = encrypt(
        cli, workdir, "--encryption", "zipcrypto", "--wz-aes-version", "2", env=ENV
    )
    assert result.returncode == 2, result
    assert "AES" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("source")
def test_none_is_not_a_method_here(cli: CliRunner, workdir: Path) -> None:
    result = encrypt(cli, workdir, "--encryption", "none", env=ENV)
    assert result.returncode == 2, result


@pytest.mark.usefixtures("source")
def test_zipcrypto_output_opens_with_the_standard_library(
    cli: CliRunner, workdir: Path
) -> None:
    encrypt(cli, workdir, "--encryption", "zipcrypto", env=ENV)
    with zipfile.ZipFile(workdir / "out.zip") as zf:
        assert zf.read("run.sh", pwd=PW) == b"#!/bin/sh\necho hi\n"


@pytest.mark.usefixtures("source")
def test_zipcrypto_warns_but_still_works(cli: CliRunner, workdir: Path) -> None:
    result = encrypt(cli, workdir, "--encryption", "zipcrypto", env=ENV)
    assert result.returncode == 0, result
    assert "weak legacy cipher" in result.stderr
    quiet = encrypt(cli, workdir, "--encryption", "zipcrypto", "--force", "-q", env=ENV)
    assert quiet.stderr == ""


@pytest.mark.usefixtures("source")
def test_aes_does_not_warn(cli: CliRunner, workdir: Path) -> None:
    assert encrypt(cli, workdir, env=ENV).stderr == ""


# --- password sources ---------------------------------------------------------------


@pytest.mark.usefixtures("source")
def test_password_from_a_file_without_its_newline(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "pw").write_text(PASSWORD + "\n")
    result = encrypt(cli, workdir, "--password-file", str(workdir / "pw"))
    assert result.returncode == 0, result
    assert matches(cli, workdir / "out.zip", PASSWORD)


@pytest.mark.usefixtures("source")
def test_password_from_standard_input(cli: CliRunner, workdir: Path) -> None:
    result = encrypt(cli, workdir, "--password-stdin", stdin=PASSWORD + "\nignored\n")
    assert result.returncode == 0, result
    assert matches(cli, workdir / "out.zip", PASSWORD)


@pytest.mark.usefixtures("source")
def test_password_from_the_environment(cli: CliRunner, workdir: Path) -> None:
    assert encrypt(cli, workdir, env=ENV).returncode == 0
    assert matches(cli, workdir / "out.zip", PASSWORD)


@pytest.mark.usefixtures("source")
def test_no_password_and_no_terminal_is_a_usage_error(
    cli: CliRunner, workdir: Path
) -> None:
    result = encrypt(cli, workdir)
    assert result.returncode == 2, result
    assert "no password given" in result.stderr
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


@pytest.mark.usefixtures("source")
def test_prompt_needs_a_terminal(cli: CliRunner, workdir: Path) -> None:
    result = encrypt(cli, workdir, "--password-prompt", stdin="x\n")
    assert result.returncode == 2, result
    assert "--password-prompt needs a terminal" in result.stderr


@pytest.mark.usefixtures("source")
def test_a_password_file_wins_over_the_environment(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "pw").write_text("from the file\n")
    result = encrypt(cli, workdir, "--password-file", str(workdir / "pw"), env=ENV)
    assert result.returncode == 0, result
    assert matches(cli, workdir / "out.zip", "from the file")
    assert not matches(cli, workdir / "out.zip", PASSWORD)


@pytest.mark.usefixtures("source")
def test_a_file_and_standard_input_that_differ_are_refused(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "pw").write_text("one password\n")
    result = encrypt(
        cli, workdir, "--password-file", str(workdir / "pw"), "--password-stdin",
        stdin="second\n",
    )  # fmt: skip
    assert result.returncode == 2, result
    assert "one password" in result.stderr
    assert not (workdir / "out.zip").exists()


@needs_pty
def test_the_password_is_asked_for_twice_at_a_terminal(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    result, prompts = terminal(
        "encrypt", str(source), str(workdir / "out.zip"),
        replies=["typed secret", "typed secret"],
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 2
    assert "Confirm password" in result.stderr
    assert matches(cli, workdir / "out.zip", "typed secret")
    assert "typed secret" not in result.stdout + result.stderr


@needs_pty
def test_a_mismatched_confirmation_writes_nothing(workdir: Path, source: Path) -> None:
    result, _ = terminal(
        "encrypt", str(source), str(workdir / "out.zip"),
        replies=["one", "two"],
    )  # fmt: skip
    assert result.returncode == 2, result
    assert "do not match" in result.stderr
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


@needs_pty
def test_an_empty_password_at_the_prompt_writes_nothing(
    workdir: Path, source: Path
) -> None:
    result, prompts = terminal(
        "encrypt", str(source), str(workdir / "out.zip"),
        replies=[""],
    )  # fmt: skip
    assert result.returncode == 2, result
    assert prompts == 1
    assert "no password entered" in result.stderr
    assert not (workdir / "out.zip").exists()


@needs_pty
@pytest.mark.skipif(
    sys.version_info >= (3, 14), reason="Ctrl-D does not end masked input"
)
def test_end_of_input_at_the_prompt_writes_nothing(workdir: Path, source: Path) -> None:
    result, _ = terminal(
        "encrypt", str(source), str(workdir / "out.zip"),
        replies=[END_OF_INPUT],
    )  # fmt: skip
    assert result.returncode == 2, result
    assert not (workdir / "out.zip").exists()


@needs_pty
def test_interrupting_at_the_prompt_leaves_nothing(workdir: Path, source: Path) -> None:
    result, _ = terminal(
        "encrypt", str(source), str(workdir / "out.zip"),
        interrupt_at_prompt=1,
    )  # fmt: skip
    assert result.returncode == 130, result
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


@needs_pty
@pytest.mark.skipif(sys.version_info < (3, 14), reason="masking needs Python 3.14")
def test_the_typed_password_is_masked_on_3_14(workdir: Path, source: Path) -> None:
    result, _ = terminal(
        "encrypt", str(source), str(workdir / "out.zip"), replies=["abc", "abc"]
    )
    assert result.returncode == 0, result
    assert "***" in result.stderr


# --- --match ----------------------------------------------------------------------


def test_match_protects_only_the_matching_files(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    result = encrypt(cli, workdir, "--match", "docs/**", env=ENV)
    assert result.returncode == 0, result
    got = schemes(workdir / "out.zip")
    assert got["docs/readme.txt"] == got["docs/data.bin"] == "aes256"
    assert {v for k, v in got.items() if not k.startswith("docs/")} == {"none"}
    assert snapshot(workdir / "out.zip", PW) == snapshot(source)
    assert "2 encrypted" in result.stdout


@pytest.mark.usefixtures("source")
def test_match_may_be_repeated(cli: CliRunner, workdir: Path) -> None:
    encrypt(cli, workdir, "--match", "*.sh", "--match", "notes/*", env=ENV)
    got = schemes(workdir / "out.zip")
    assert {k for k, v in got.items() if v != "none"} == {
        "run.sh",
        "notes/ünïcode ✓.txt",
    }


@pytest.mark.usefixtures("source")
def test_a_star_stays_within_one_directory_level(cli: CliRunner, workdir: Path) -> None:
    encrypt(cli, workdir, "--match", "*.txt", env=ENV)
    got = schemes(workdir / "out.zip")
    assert {k for k, v in got.items() if v != "none"} == {"empty.txt"}


@pytest.mark.usefixtures("source")
def test_a_member_can_be_named_literally(cli: CliRunner, workdir: Path) -> None:
    encrypt(cli, workdir, "--match", "notes/ünïcode ✓.txt", env=ENV)
    got = schemes(workdir / "out.zip")
    assert {k for k, v in got.items() if v != "none"} == {"notes/ünïcode ✓.txt"}


@pytest.mark.usefixtures("source")
def test_a_pattern_that_matches_nothing_is_an_error(
    cli: CliRunner, workdir: Path
) -> None:
    result = encrypt(cli, workdir, "--match", "docs/**", "--match", "typo/**", env=ENV)
    assert result.returncode == 2, result
    assert "typo/**" in result.stderr
    assert "docs/**" not in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("source")
def test_a_directory_name_matches_the_files_under_it(
    cli: CliRunner, workdir: Path
) -> None:
    result = encrypt(cli, workdir, "--match", "docs/", env=ENV)
    assert result.returncode == 0, result
    got = schemes(workdir / "out.zip")
    assert got["docs/readme.txt"] == got["docs/data.bin"] == "aes256"
    assert {v for k, v in got.items() if not k.startswith("docs/")} == {"none"}


def test_a_bad_pattern_does_not_prompt(workdir: Path, source: Path) -> None:
    if not HAS_PTY:
        pytest.skip("needs a pseudo-terminal")
    result, prompts = terminal(
        "encrypt", str(source), str(workdir / "out.zip"), "--match", "typo",
    )  # fmt: skip
    assert result.returncode == 2, result
    assert prompts == 0


# --- what cannot be encrypted --------------------------------------------------------


def test_an_already_encrypted_input_points_at_rewrite(
    cli: CliRunner, workdir: Path
) -> None:
    make_source(
        workdir / "in.zip",
        encryption=ziplet.WZ_AES,
        password=PW,
        extra=ziplet.ZipFileExtra(wz_aes_nbits=256),
    )
    result = encrypt(cli, workdir, env=ENV)
    assert result.returncode == 1, result
    assert "6 members" in result.stderr
    assert "already encrypted" in result.stderr
    assert "ziplet rewrite" in result.stderr
    assert not (workdir / "out.zip").exists()


def test_a_partly_encrypted_input_is_refused_too(cli: CliRunner, workdir: Path) -> None:
    make_mixed(workdir / "in.zip")
    result = encrypt(cli, workdir, "--match", "c.txt", env=ENV)
    assert result.returncode == 1, result
    assert "3 members" in result.stderr
    assert "a.txt" in result.stderr


def test_an_archive_without_files_has_nothing_to_encrypt(
    cli: CliRunner, workdir: Path
) -> None:
    with ZipFile(workdir / "in.zip", "w") as zf:
        zf.mkdir("only/")
    result = encrypt(cli, workdir, env=ENV)
    assert result.returncode == 1, result
    assert "no files to encrypt" in result.stderr


def test_an_empty_archive_has_nothing_to_encrypt(cli: CliRunner, workdir: Path) -> None:
    with ZipFile(workdir / "in.zip", "w"):
        pass
    result = encrypt(cli, workdir, env=ENV)
    assert result.returncode == 1, result


def test_a_single_empty_file_is_encrypted(cli: CliRunner, workdir: Path) -> None:
    write_archive(workdir / "in.zip", [("nothing", b"")])
    result = encrypt(cli, workdir, env=ENV)
    assert result.returncode == 0, result
    assert snapshot(workdir / "out.zip", PW)["nothing"][5] == b""
    assert schemes(workdir / "out.zip") == {"nothing": "aes256"}
