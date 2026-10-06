"""``zipctl decrypt``: an encrypted archive in, an unencrypted copy out."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from typing_extensions import Unpack

import zipctl
from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.rewrite_support import (
    OTHER,
    OTHER_PW,
    PASSWORD,
    PW,
    leftovers,
    make_mixed,
    make_source,
    schemes,
    snapshot,
)
from tests.functional.cli.support import HAS_PTY, Result, RunOptions, write_archive
from tests.functional.cli.support import run_in_terminal as terminal
from zipctl import ZipFile

ENV = {"ZIPCTL_PASSWORD": PASSWORD}
needs_pty = pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")
WZ_AES = zipctl.WZ_AES


def encrypted_source(
    workdir: Path, method: str = "aes256", version: int | None = None
) -> Path:
    if method == "zipcrypto":
        return make_source(
            workdir / "in.zip", encryption=zipctl.ZIP_CRYPTO, password=PW
        )
    bits = int(method[3:])
    return make_source(
        workdir / "in.zip",
        encryption=WZ_AES,
        password=PW,
        extra=zipctl.ZipFileExtra(wz_aes_nbits=bits, force_wz_aes_version=version),
    )


def decrypt(
    cli: CliRunner, workdir: Path, *args: str, **kw: Unpack[RunOptions]
) -> Result:
    return cli(
        "decrypt", str(workdir / "in.zip"), str(workdir / "out.zip"), *args, **kw
    )


@pytest.mark.parametrize("method", ["aes128", "aes192", "aes256", "zipcrypto"])
def test_every_method_decrypts_to_the_same_files(
    cli: CliRunner, workdir: Path, method: str
) -> None:
    source = encrypted_source(workdir, method)
    result = decrypt(cli, workdir, env=ENV)
    assert result.returncode == 0, result
    out = workdir / "out.zip"
    assert set(schemes(out).values()) == {"none"}
    assert snapshot(out) == snapshot(source, PW)
    assert "6 files, 2 directories (verified)" in result.stdout


def test_aes_version_one_input_decrypts(cli: CliRunner, workdir: Path) -> None:
    encrypted_source(workdir, "aes256", version=1)
    assert decrypt(cli, workdir, env=ENV).returncode == 0
    assert set(schemes(workdir / "out.zip").values()) == {"none"}


def test_the_output_needs_no_password(cli: CliRunner, workdir: Path) -> None:
    encrypted_source(workdir)
    decrypt(cli, workdir, env=ENV)
    result = cli("test", str(workdir / "out.zip"))
    assert result.returncode == 0, result


def test_the_input_is_left_alone(cli: CliRunner, workdir: Path) -> None:
    source = encrypted_source(workdir)
    before = source.read_bytes()
    decrypt(cli, workdir, env=ENV)
    assert source.read_bytes() == before


# --- passwords ----------------------------------------------------------------------


def test_password_from_standard_input(cli: CliRunner, workdir: Path) -> None:
    encrypted_source(workdir)
    result = decrypt(cli, workdir, "--password-stdin", stdin=PASSWORD + "\n")
    assert result.returncode == 0, result


def test_a_wrong_password_writes_nothing(cli: CliRunner, workdir: Path) -> None:
    encrypted_source(workdir)
    result = decrypt(cli, workdir, env={"ZIPCTL_PASSWORD": "wrong"})
    assert result.returncode == 1, result
    assert "wrong password" in result.stderr
    assert "docs/readme.txt" in result.stderr
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


def test_a_missing_password_without_a_terminal_writes_nothing(
    cli: CliRunner, workdir: Path
) -> None:
    encrypted_source(workdir)
    result = decrypt(cli, workdir)
    assert result.returncode == 1, result
    assert "password required" in result.stderr
    assert not (workdir / "out.zip").exists()


def test_the_old_password_variable_is_not_used_here(
    cli: CliRunner, workdir: Path
) -> None:
    encrypted_source(workdir)
    result = decrypt(cli, workdir, env={"ZIPCTL_OLD_PASSWORD": PASSWORD})
    assert result.returncode == 1, result
    assert "password required (use --password-file" in result.stderr


def test_the_password_is_prompted_for_once(cli: CliRunner, workdir: Path) -> None:
    encrypted_source(workdir)
    result, prompts = cli.terminal(
        "decrypt",
        str(workdir / "in.zip"),
        str(workdir / "out.zip"),
        replies=[PASSWORD],
    )
    assert result.returncode == 0, result
    assert prompts == 1
    assert "Password for docs/readme.txt" in result.stderr


def test_a_wrong_answer_is_retried(cli: CliRunner, workdir: Path) -> None:
    encrypted_source(workdir)
    result, prompts = cli.terminal(
        "decrypt",
        str(workdir / "in.zip"),
        str(workdir / "out.zip"),
        replies=["nope", PASSWORD],
    )
    assert result.returncode == 0, result
    assert prompts == 2
    assert "incorrect password" in result.stderr


def test_giving_up_at_the_prompt_writes_nothing(cli: CliRunner, workdir: Path) -> None:
    encrypted_source(workdir)
    result, prompts = cli.terminal(
        "decrypt", str(workdir / "in.zip"), str(workdir / "out.zip"), replies=[""],
    )  # fmt: skip
    assert result.returncode == 1, result
    assert prompts == 1
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


def test_three_wrong_answers_write_nothing(cli: CliRunner, workdir: Path) -> None:
    encrypted_source(workdir)
    result, prompts = cli.terminal(
        "decrypt",
        str(workdir / "in.zip"),
        str(workdir / "out.zip"),
        replies=["a", "b", "c"],
    )
    assert result.returncode == 1, result
    assert prompts == 3
    assert not (workdir / "out.zip").exists()


@needs_pty
def test_interrupting_leaves_nothing(workdir: Path) -> None:
    encrypted_source(workdir)
    result, _ = terminal(
        "decrypt",
        str(workdir / "in.zip"),
        str(workdir / "out.zip"),
        interrupt_at_prompt=1,
    )
    assert result.returncode == 130, result
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


# --- mixed archives -----------------------------------------------------------------


def test_plain_members_stay_plain(cli: CliRunner, workdir: Path) -> None:
    write_archive(
        workdir / "in.zip", [("one", b"1")], encryption=WZ_AES, password=PW,
        extra=zipctl.ZipFileExtra(wz_aes_nbits=256),
    )  # fmt: skip
    with ZipFile(workdir / "in.zip", "a") as zf:
        zf.writestr("two", b"2")
    result = decrypt(cli, workdir, env=ENV)
    assert result.returncode == 0, result
    assert schemes(workdir / "out.zip") == {"one": "none", "two": "none"}
    assert snapshot(workdir / "out.zip")["two"][5] == b"2"


def test_one_password_for_an_archive_of_two_fails_and_names_the_member(
    cli: CliRunner, workdir: Path
) -> None:
    make_mixed(workdir / "in.zip")
    result = decrypt(cli, workdir, env=ENV)
    assert result.returncode == 1, result
    assert "b.txt" in result.stderr
    assert not (workdir / "out.zip").exists()


def test_an_archive_with_two_passwords_prompts_for_each(
    cli: CliRunner, workdir: Path
) -> None:
    make_mixed(workdir / "in.zip")
    result, prompts = cli.terminal(
        "decrypt",
        str(workdir / "in.zip"),
        str(workdir / "out.zip"),
        replies=[PASSWORD, OTHER],
    )
    assert result.returncode == 0, result
    assert prompts == 2
    assert schemes(workdir / "out.zip") == dict.fromkeys(
        "a.txt b.txt c.txt d.txt".split(), "none"
    )
    assert snapshot(workdir / "out.zip")["b.txt"][5] == b"bravo"


def test_an_unencrypted_input_is_an_error(cli: CliRunner, workdir: Path) -> None:
    make_source(workdir / "in.zip")
    result = decrypt(cli, workdir, env=ENV)
    assert result.returncode == 1, result
    assert "no encrypted members" in result.stderr
    assert not (workdir / "out.zip").exists()


# --- --match ----------------------------------------------------------------------


def test_match_decrypts_only_what_matches_and_keeps_the_rest_protected(
    cli: CliRunner, workdir: Path
) -> None:
    source = encrypted_source(workdir)
    result = decrypt(cli, workdir, "--match", "docs/**", env=ENV)
    assert result.returncode == 0, result
    got = schemes(workdir / "out.zip")
    assert got["docs/readme.txt"] == got["docs/data.bin"] == "none"
    assert {v for k, v in got.items() if not k.startswith("docs/")} == {"aes256"}
    assert snapshot(workdir / "out.zip", PW) == snapshot(source, PW)
    assert "4 encrypted" in result.stdout


def single_password_mix(path: Path) -> Path:
    """a: AES-256, b: AES-192 (version 1), c: plain, d: ZipCrypto; one password."""
    with ZipFile(path, "w") as zf:
        for name, bits, version in (("a.txt", 256, None), ("b.txt", 192, 1)):
            zf.writestr(
                name,
                name.encode() * 50,
                encryption=WZ_AES,
                password=PW,
                extra=zipctl.ZipFileExtra(
                    wz_aes_nbits=bits, force_wz_aes_version=version
                ),
            )
        zf.writestr("c.txt", b"charlie")
        zf.writestr("d.txt", b"delta" * 50, encryption=zipctl.ZIP_CRYPTO, password=PW)
    return path


def test_what_is_kept_keeps_its_scheme_and_password(
    cli: CliRunner, workdir: Path
) -> None:
    source = single_password_mix(workdir / "in.zip")
    result = decrypt(cli, workdir, "--match", "a.txt", env=ENV)
    assert result.returncode == 0, result
    assert schemes(workdir / "out.zip") == {
        "a.txt": "none",
        "b.txt": "aes192-v1",
        "c.txt": "none",
        "d.txt": "zipcrypto",
    }
    assert snapshot(workdir / "out.zip", PW) == snapshot(source, PW)
    assert "2 encrypted" in result.stdout


def test_kept_members_with_another_password_are_not_asked_for(
    cli: CliRunner,
    workdir: Path,
) -> None:
    make_mixed(workdir / "in.zip")
    result, prompts = cli.terminal(
        "decrypt", str(workdir / "in.zip"), str(workdir / "out.zip"),
        "--match", "a.txt", replies=[PASSWORD],
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 1
    assert schemes(workdir / "out.zip") == {
        "a.txt": "none",
        "b.txt": "aes192-v1",
        "c.txt": "none",
        "d.txt": "zipcrypto",
    }
    assert (
        snapshot(workdir / "out.zip", {"b.txt": OTHER_PW, "d.txt": PW})["b.txt"][5]
        == b"bravo"
    )


def test_several_patterns_may_be_given(cli: CliRunner, workdir: Path) -> None:
    single_password_mix(workdir / "in.zip")
    decrypt(cli, workdir, "--match", "a.txt", "--match", "d.txt", env=ENV)
    assert schemes(workdir / "out.zip") == {
        "a.txt": "none",
        "b.txt": "aes192-v1",
        "c.txt": "none",
        "d.txt": "none",
    }


def test_a_pattern_that_matches_no_encrypted_member_is_an_error(
    cli: CliRunner, workdir: Path
) -> None:
    single_password_mix(workdir / "in.zip")
    for pattern in ("typo", "c.txt"):  # c.txt exists but is not encrypted
        result = decrypt(cli, workdir, "--match", pattern, env=ENV)
        assert result.returncode == 2, result
        assert f"'{pattern}'" in result.stderr
        assert not (workdir / "out.zip").exists()


def test_a_kept_member_needs_no_password_and_is_copied_as_stored(
    cli: CliRunner, workdir: Path
) -> None:
    make_mixed(workdir / "in.zip")  # b.txt has its own password
    result = decrypt(cli, workdir, "--match", "a.txt", env=ENV)
    assert result.returncode == 0, result
    with ZipFile(workdir / "in.zip") as before, ZipFile(workdir / "out.zip") as after:
        old, new = before.getinfo("b.txt"), after.getinfo("b.txt")
        assert (new.CRC, new.compress_size, new.flag_bits) == (
            old.CRC,
            old.compress_size,
            old.flag_bits,
        )
        assert after.read("b.txt", pwd=OTHER_PW) == b"bravo"


def test_a_kept_member_with_a_cp437_name_passes_verification(
    cli: CliRunner, workdir: Path
) -> None:
    path = workdir / "in.zip"
    with ZipFile(path, "w") as zf:
        zf.writestr("é.txt", b"echo" * 50, encryption=zipctl.ZIP_CRYPTO, password=PW)
        zf.writestr("c.txt", b"charlie", encryption=zipctl.ZIP_CRYPTO, password=PW)
    # Clear bit 11 so the name reads as cp437, as old Windows tools wrote it;
    # the copy encodes it as UTF-8 and sets the bit.  index() finds the first
    # local and central headers, which are é.txt's because it is written first.
    data = bytearray(path.read_bytes())
    for signature, flags in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = data.index(signature) + flags
        data[at + 1] &= ~0x08
    path.write_bytes(data)
    result = decrypt(cli, workdir, "--match", "c.txt", env=ENV)
    assert result.returncode == 0, result
    with ZipFile(workdir / "out.zip") as zf:
        assert zf.read("├⌐.txt", PW) == b"echo" * 50


def test_a_kept_aes2_member_that_stores_its_crc_passes_verification(
    cli: CliRunner, workdir: Path
) -> None:
    path = workdir / "in.zip"
    aes1 = zipctl.ZipFileExtra(wz_aes_nbits=256, force_wz_aes_version=1)
    with ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"alpha" * 50, encryption=WZ_AES, password=PW, extra=aes1)
        zf.writestr("c.txt", b"charlie", encryption=WZ_AES, password=PW, extra=aes1)
    # Mark a.txt AE-2 but keep its CRC, as some writers do; a copy writes the
    # CRC of an AE-2 member as 0.  index() finds a.txt's headers first.
    data = bytearray(path.read_bytes())
    for signature in (b"PK\x03\x04", b"PK\x01\x02"):
        field = data.index(b"\x01\x99\x07\x00", data.index(signature))
        struct.pack_into("<H", data, field + 4, 2)
    path.write_bytes(data)
    result = decrypt(cli, workdir, "--match", "c.txt", env=ENV)
    assert result.returncode == 0, result
    with ZipFile(workdir / "out.zip") as zf:
        assert zf.getinfo("a.txt").aes_extra is not None
        assert zf.read("a.txt", PW) == b"alpha" * 50
