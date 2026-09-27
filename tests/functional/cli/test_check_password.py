"""``ziplet check-password``: one password against the encrypted members."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import ziplet
from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.reports import CheckPasswordReport, load_json
from tests.functional.cli.support import (
    HAS_PTY,
    PASSWORD,
    Result,
    data_offset,
    flip_byte,
    write_archive,
)
from tests.functional.cli.support import run_in_terminal as terminal
from ziplet import ZipFile

PW = PASSWORD.encode()
BODY = b"secret payload " * 100
ENV = {"ZIPLET_PASSWORD": PASSWORD}
NOTE = "(verifier only; use --full to authenticate the data)"
needs_pty = pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")


@pytest.fixture
def shared(workdir: Path) -> Path:
    return write_archive(
        workdir / "shared.zip",
        [("a.txt", BODY), ("d/b.txt", BODY), ("c.bin", BODY)],
        encryption=ziplet.WZ_AES,
        password=PW,
    )


@pytest.fixture
def per_member(workdir: Path) -> Path:
    path = workdir / "per.zip"
    with ZipFile(path, "w", encryption=ziplet.WZ_AES) as zf:
        zf.writestr("alpha.txt", BODY, password=b"pass-alpha")
        zf.writestr("docs/beta.txt", BODY, password=b"pass-beta")
        zf.writestr("docs/deep/gamma.txt", BODY, password=b"pass-beta")
        zf.writestr("plain.txt", BODY, encryption=None)
    return path


def _json(result: Result) -> CheckPasswordReport:
    assert result.stderr == "", result
    return load_json(result, CheckPasswordReport)


def _statuses(document: CheckPasswordReport) -> dict[str, str]:
    return {m["name"]: m["status"] for m in document["members"]}


# --- the verdict


def test_the_right_password_fits_every_member(cli: CliRunner, shared: Path) -> None:
    result = cli("check-password", str(shared), env=ENV)
    assert result.returncode == 0, result
    assert result.stdout == f"Checked 3 encrypted members: all OK {NOTE}\n"
    assert result.stderr == ""


def test_full_authenticates_the_data_and_drops_the_note(
    cli: CliRunner, shared: Path
) -> None:
    result = cli("check-password", "--full", str(shared), env=ENV)
    assert result.returncode == 0, result
    assert result.stdout == "Checked 3 encrypted members: all OK\n"


def test_a_wrong_password_names_every_rejected_member(
    cli: CliRunner, shared: Path
) -> None:
    result = cli("check-password", str(shared), env={"ZIPLET_PASSWORD": "nope"})
    assert result.returncode == 1, result
    assert result.stdout.splitlines() == [
        "FAILED  a.txt: password does not match",
        "FAILED  d/b.txt: password does not match",
        "FAILED  c.bin: password does not match",
        "",
        "Checked 3 encrypted members: 3 failed",
    ]


def test_a_password_that_fits_only_some_members_fails(
    cli: CliRunner, per_member: Path
) -> None:
    result = cli(
        "check-password", str(per_member), env={"ZIPLET_PASSWORD": "pass-beta"}
    )
    assert result.returncode == 1, result
    assert result.stdout.splitlines() == [
        "FAILED  alpha.txt: password does not match",
        "",
        f"Checked 3 encrypted members: 1 failed {NOTE}",
    ]


def test_verbose_lists_members_that_fit_and_unencrypted_ones(
    cli: CliRunner, per_member: Path
) -> None:
    result = cli(
        "check-password", "-v", str(per_member), env={"ZIPLET_PASSWORD": "pass-beta"}
    )
    lines = result.stdout.splitlines()
    assert "FAILED  alpha.txt: password does not match" in lines
    assert "OK      docs/beta.txt" in lines
    assert "OK      docs/deep/gamma.txt" in lines
    assert "SKIP    plain.txt: not encrypted" in lines


def test_an_archive_without_encrypted_members_has_nothing_to_check(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(workdir / "plain.zip", [("a", b"1")])
    result = cli("check-password", str(archive), env=ENV)
    assert result.returncode == 0, result
    assert result.stdout == "No encrypted members to check\n"


@pytest.mark.parametrize(
    ("kind", "extra"),
    [
        ("aes128", ziplet.ZipFileExtra(wz_aes_nbits=128)),
        ("aes192", ziplet.ZipFileExtra(wz_aes_nbits=192)),
        ("aes256", ziplet.ZipFileExtra(wz_aes_nbits=256)),
        ("aes256-v1", ziplet.ZipFileExtra(force_wz_aes_version=1)),
    ],
)
def test_every_aes_flavour(
    cli: CliRunner, workdir: Path, kind: str, extra: ziplet.ZipFileExtra
) -> None:
    archive = write_archive(
        workdir / f"{kind}.zip",
        [("a", BODY)],
        encryption=ziplet.WZ_AES,
        password=PW,
        extra=extra,
    )
    assert cli("check-password", "--full", str(archive), env=ENV).returncode == 0
    wrong = cli("check-password", str(archive), env={"ZIPLET_PASSWORD": "nope"})
    assert wrong.returncode == 1, wrong


def test_zipcrypto_archives_are_checked_too(cli: CliRunner, workdir: Path) -> None:
    archive = write_archive(
        workdir / "zc.zip",
        [("a", BODY), ("b", BODY)],
        encryption=ziplet.ZIP_CRYPTO,
        password=PW,
    )
    assert cli("check-password", str(archive), env=ENV).returncode == 0
    assert cli("check-password", "--full", str(archive), env=ENV).returncode == 0
    # --full is definitive, so a wrong password fails however lucky the verifier is
    wrong = cli("check-password", "--full", str(archive), env={"ZIPLET_PASSWORD": "x"})
    assert wrong.returncode == 1, wrong
    assert wrong.stdout.count("\n") == 4


def test_full_finds_damage_that_the_verifier_check_cannot(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(
        workdir / "damaged.zip", [("a", BODY)], encryption=ziplet.WZ_AES, password=PW
    )
    flip_byte(archive, data_offset(archive, "a") + 40)
    assert cli("check-password", str(archive), env=ENV).returncode == 0
    full = cli("check-password", "--full", str(archive), env=ENV)
    assert full.returncode == 1, full
    assert (
        full.stdout.splitlines()[0]
        == "FAILED  a: password matches but the data is corrupt"
    )


def test_a_damaged_local_header_is_reported_as_corrupt(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(
        workdir / "damaged.zip", [("a", BODY)], encryption=ziplet.WZ_AES, password=PW
    )
    flip_byte(archive, 0)  # the local header signature
    result = cli("check-password", str(archive), env=ENV)
    assert result.returncode == 1, result
    assert "FAILED  a: password matches but the data is corrupt" in result.stdout


# --- choosing members


def test_named_members_only(cli: CliRunner, per_member: Path) -> None:
    result = cli(
        "check-password",
        str(per_member),
        "alpha.txt",
        env={"ZIPLET_PASSWORD": "pass-alpha"},
    )
    assert result.returncode == 0, result
    assert result.stdout.startswith("Checked 1 encrypted member: all OK ")


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("*.txt", {"alpha.txt", "plain.txt"}),
        ("docs/*", {"docs/beta.txt"}),
        ("docs/**", {"docs/beta.txt", "docs/deep/gamma.txt"}),
        ("docs/**/*.txt", {"docs/deep/gamma.txt"}),
        ("?lpha.txt", {"alpha.txt"}),
        ("[ap]*.txt", {"alpha.txt", "plain.txt"}),
        ("docs/deep/gamma.txt", {"docs/deep/gamma.txt"}),
    ],
)
def test_patterns_pick_members_the_way_archive_paths_read(
    cli: CliRunner, per_member: Path, pattern: str, expected: set[str]
) -> None:
    document = _json(
        cli(
            "check-password",
            "--json",
            str(per_member),
            pattern,
            env={"ZIPLET_PASSWORD": "pass-beta"},
        )  # fmt: skip
    )
    assert set(_statuses(document)) == expected


def test_several_patterns_are_combined(cli: CliRunner, per_member: Path) -> None:
    document = _json(
        cli(
            "check-password",
            "--json",
            str(per_member),
            "alpha.txt",
            "docs/*",
            env={"ZIPLET_PASSWORD": "pass-beta"},
        )  # fmt: skip
    )
    assert set(_statuses(document)) == {"alpha.txt", "docs/beta.txt"}


def test_a_name_with_glob_characters_matches_itself(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(
        workdir / "odd.zip",
        [("[odd]*.txt", BODY), ("other", BODY)],
        encryption=ziplet.WZ_AES,
        password=PW,
    )
    document = _json(
        cli("check-password", "--json", str(archive), "[odd]*.txt", env=ENV)
    )
    assert set(_statuses(document)) == {"[odd]*.txt"}


def test_a_pattern_matching_nothing_is_an_error(
    cli: CliRunner, per_member: Path
) -> None:
    result = cli(
        "check-password", str(per_member), "alpha.txt", "nothing/*", "x\x1b[2J",
        env=ENV,
    )  # fmt: skip
    assert result.returncode == 2, result
    assert result.stdout == ""
    assert "no member matches 'nothing/*', 'x\\x1b[2J'" in result.stderr


# --- output


def test_json_report(cli: CliRunner, per_member: Path) -> None:
    result = cli(
        "check-password", "--json", "--full", str(per_member),
        env={"ZIPLET_PASSWORD": "pass-beta"},
    )  # fmt: skip
    assert result.returncode == 1
    document = _json(result)
    assert document["archive"] == str(per_member)
    assert (document["ok"], document["full"]) == (False, True)
    assert (document["encrypted"], document["accepted"]) == (3, 2)
    assert (document["rejected"], document["corrupt"]) == (1, 0)
    assert _statuses(document) == {
        "alpha.txt": "rejected",
        "docs/beta.txt": "accepted",
        "docs/deep/gamma.txt": "accepted",
        "plain.txt": "unencrypted",
    }


def test_json_report_of_a_passing_check(cli: CliRunner, shared: Path) -> None:
    result = cli("check-password", "--json", str(shared), env=ENV)
    assert result.returncode == 0
    assert _json(result)["ok"] is True


def test_hostile_member_names_are_escaped_but_exact_in_json(
    cli: CliRunner, workdir: Path
) -> None:
    name = "evil\x1b[31m\nname"
    archive = write_archive(
        workdir / "h.zip", [(name, BODY)], encryption=ziplet.WZ_AES, password=PW
    )
    result = cli("check-password", str(archive), env={"ZIPLET_PASSWORD": "wrong"})
    assert "\x1b" not in result.stdout
    assert "FAILED  evil\\x1b[31m\\x0aname: password does not match" in result.stdout
    document = _json(
        cli("check-password", "--json", str(archive), env={"ZIPLET_PASSWORD": "wrong"})
    )
    assert list(_statuses(document)) == [name]


def test_the_password_is_never_printed(cli: CliRunner, per_member: Path) -> None:
    for extra in ([], ["-v"], ["--json"], ["--full"]):
        result = cli(
            "check-password",
            *extra,
            str(per_member),
            env={"ZIPLET_PASSWORD": "pass-beta"},
        )
        assert "pass-beta" not in result.stdout + result.stderr


def test_the_archive_is_never_modified(cli: CliRunner, shared: Path) -> None:
    before = shared.read_bytes()
    cli("check-password", "--full", str(shared), env=ENV)
    assert shared.read_bytes() == before


# --- where the password comes from


def test_password_file(cli: CliRunner, shared: Path, workdir: Path) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(PW + b"\nsecond line ignored\n")
    result = cli("check-password", str(shared), "--password-file", str(passfile))
    assert result.returncode == 0, result


def test_password_from_standard_input(cli: CliRunner, shared: Path) -> None:
    result = cli(
        "check-password", str(shared), "--password-stdin", stdin=PASSWORD + "\n"
    )
    assert result.returncode == 0, result


def test_a_password_that_is_not_valid_utf8_survives_the_file_route(
    cli: CliRunner, workdir: Path
) -> None:
    raw = b"\xff\xfe binary \x80"
    archive = write_archive(
        workdir / "b.zip", [("a", BODY)], encryption=ziplet.WZ_AES, password=raw
    )
    passfile = workdir / "pw"
    passfile.write_bytes(raw + b"\n")
    result = cli(
        "check-password", "--full", str(archive), "--password-file", str(passfile)
    )
    assert result.returncode == 0, result


def test_the_file_beats_the_environment(
    cli: CliRunner, shared: Path, workdir: Path
) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(b"wrong\n")
    result = cli(
        "check-password", str(shared), "--password-file", str(passfile), env=ENV
    )
    assert result.returncode == 1, "the environment password must not be tried"


def test_two_different_passwords_are_a_usage_error(
    cli: CliRunner, shared: Path, workdir: Path
) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(b"one\n")
    result = cli(
        "check-password", str(shared), "--password-file", str(passfile),
        "--password-stdin", stdin="two\n",
    )  # fmt: skip
    assert result.returncode == 2, result
    assert "tests one password" in result.stderr


def test_the_same_password_twice_is_fine(
    cli: CliRunner, shared: Path, workdir: Path
) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(PW + b"\n")
    result = cli(
        "check-password", str(shared), "--password-file", str(passfile),
        "--password-stdin", stdin=PASSWORD + "\n",
    )  # fmt: skip
    assert result.returncode == 0, result


def test_without_any_source_and_without_a_terminal_it_is_a_usage_error(
    cli: CliRunner, shared: Path
) -> None:
    result = cli("check-password", str(shared))
    assert result.returncode == 2, result
    assert "no password given" in result.stderr
    assert "--password-file" in result.stderr


def test_prompting_without_a_terminal_is_a_usage_error(
    cli: CliRunner, shared: Path
) -> None:
    result = cli("check-password", str(shared), "--password-prompt")
    assert result.returncode == 2
    assert "--password-prompt needs a terminal" in result.stderr


# --- prompting on a terminal


@needs_pty
def test_a_terminal_is_asked_for_the_password_once(shared: Path) -> None:
    result, prompts = terminal("check-password", str(shared), replies=[PASSWORD])
    assert result.returncode == 0, result
    assert prompts == 1
    assert "Password: " in result.stderr
    assert PASSWORD not in result.stdout + result.stderr


@needs_pty
def test_the_typed_password_is_masked_where_python_allows(shared: Path) -> None:
    result, _ = terminal("check-password", str(shared), replies=[PASSWORD])
    assert result.returncode == 0, result
    assert PASSWORD not in result.stderr
    assert ("*" * len(PASSWORD) in result.stderr) == (sys.version_info >= (3, 14))


@needs_pty
def test_a_wrong_typed_password_is_reported_not_retried(shared: Path) -> None:
    result, prompts = terminal("check-password", str(shared), replies=["nope"])
    assert result.returncode == 1, result
    assert prompts == 1
    assert "Checked 3 encrypted members: 3 failed" in result.stdout


@needs_pty
def test_giving_no_password_at_the_prompt_is_a_usage_error(shared: Path) -> None:
    result, prompts = terminal("check-password", str(shared), replies=[""])
    assert result.returncode == 2, result
    assert prompts == 1
    assert "no password entered" in result.stderr
    assert result.stdout == ""


@needs_pty
def test_interrupting_the_prompt_exits_130(shared: Path) -> None:
    result, _ = terminal("check-password", str(shared), interrupt_at_prompt=1)
    assert result.returncode == 130, result
    assert "Traceback" not in result.stderr


# --- damaged and missing archives


def test_bad_archives_fail_cleanly(cli: CliRunner, workdir: Path) -> None:
    missing = cli("check-password", str(workdir / "missing.zip"), env=ENV)
    assert missing.returncode == 1
    assert "cannot open" in missing.stderr
    junk = workdir / "junk.zip"
    junk.write_bytes(b"not a zip")
    result = cli("check-password", str(junk), env=ENV)
    assert result.returncode == 1
    assert "not a valid ZIP archive" in result.stderr
    assert "Traceback" not in result.stderr


def test_the_archive_is_opened_before_the_password_is_asked_for(
    cli: CliRunner, workdir: Path
) -> None:
    junk = workdir / "junk.zip"
    junk.write_bytes(b"not a zip")
    result = cli("check-password", str(junk))  # no password source at all
    assert result.returncode == 1, (
        "a bad archive is reported before the missing password"
    )


def test_a_malformed_pattern_is_a_usage_error(cli: CliRunner, shared: Path) -> None:
    result = cli("check-password", str(shared), "a**", env={"ZIPLET_PASSWORD": "x"})
    assert result.returncode == 2, result
    assert "invalid pattern" in result.stderr
    assert "Traceback" not in result.stderr


def test_no_password_is_asked_for_when_nothing_is_encrypted(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(workdir / "plain.zip", [("a", b"1")])
    result = cli("check-password", str(archive))  # no password of any kind
    assert result.returncode == 0, result
    assert result.stdout == "No encrypted members to check\n"
    as_json = load_json(
        cli("check-password", "--json", str(archive)), CheckPasswordReport
    )
    assert as_json["ok"] is True
    assert as_json["encrypted"] == 0
    assert as_json["members"] == [{"name": "a", "status": "unencrypted"}]
