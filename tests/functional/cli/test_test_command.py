"""``zipctl test``: integrity checks, failure reporting, non-interactive passwords."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import zipctl
from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.reports import VerifyReport, load_json
from tests.functional.cli.support import (
    PASSWORD,
    Result,
    data_offset,
    flip_byte,
    set_compress_type,
    set_flag_bits,
    write_archive,
)
from zipctl import ZipFile
from zipctl.compression import registry

PW = PASSWORD.encode()
BODY = b"integrity check payload " * 200


def _failed(result: Result) -> list[str]:
    return [line for line in result.stdout.splitlines() if line.startswith("FAILED")]


# --- plain archives ----------------------------------------------------------


@pytest.mark.parametrize(
    "compression",
    [zipctl.ZIP_STORED, zipctl.ZIP_DEFLATED, zipctl.ZIP_BZIP2, zipctl.ZIP_LZMA],
)
def test_intact_archive_passes(cli: CliRunner, workdir: Path, compression: int) -> None:
    path = write_archive(
        workdir / "ok.zip",
        [("a.txt", BODY), ("d/b.txt", BODY[:100]), ("empty", b"")],
        compression=compression,
    )
    result = cli("test", str(path))
    assert result.returncode == 0, result
    assert result.stdout == "Tested 3 members: all OK\n"
    assert result.stderr == ""


@pytest.mark.skipif(
    registry._registry.get(zipctl.ZIP_ZSTANDARD) is None, reason="zstd unavailable"
)
def test_zstd_archive_passes(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(
        workdir / "z.zip", [("a.txt", BODY)], compression=zipctl.ZIP_ZSTANDARD
    )
    assert cli("test", str(path)).returncode == 0


def test_verbose_lists_passing_members_and_directories(
    cli: CliRunner, workdir: Path
) -> None:
    path = workdir / "v.zip"
    with ZipFile(path, "w") as zf:
        zf.mkdir("dir")
        zf.writestr("dir/a.txt", b"a")
    result = cli("test", "-v", str(path))
    assert result.stdout.splitlines() == [
        "OK      dir/",
        "OK      dir/a.txt",
        "",
        "Tested 2 members: all OK",
    ]


def test_empty_archive_passes(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(workdir / "e.zip", [])
    result = cli("test", str(path))
    assert result.returncode == 0
    assert result.stdout == "Tested 0 members: all OK\n"


def test_large_member_is_read_across_many_chunks(cli: CliRunner, workdir: Path) -> None:
    payload = bytes(range(251)) * (3 * 1024 * 1024 // 251)
    path = write_archive(
        workdir / "big.zip", [("big.bin", payload)], compression=zipctl.ZIP_DEFLATED
    )
    assert cli("test", str(path)).returncode == 0


def test_json_report_for_a_passing_archive(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(workdir / "j.zip", [("a", b"1"), ("b", b"2")])
    result = cli("test", "--json", str(path))
    assert result.returncode == 0, result
    assert json.loads(result.stdout) == {
        "archive": str(path),
        "ok": True,
        "tested": 2,
        "failed": 0,
        "members": [
            {"name": "a", "status": "ok", "detail": None},
            {"name": "b", "status": "ok", "detail": None},
        ],
    }


# --- damaged archives --------------------------------------------------------


def test_corrupted_data_fails_the_member_and_only_that_member(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(
        workdir / "bad.zip", [("good.txt", BODY), ("bad.txt", BODY), ("also.txt", BODY)]
    )
    flip_byte(path, data_offset(path, "bad.txt") + 5)
    result = cli("test", "-v", str(path))
    assert result.returncode == 1, result
    assert "OK      good.txt" in result.stdout
    assert "OK      also.txt" in result.stdout
    (failure,) = _failed(result)
    assert failure.startswith("FAILED  bad.txt: ")
    assert "CRC" in failure
    assert result.stdout.splitlines()[-2:] == ["", "Tested 3 members: 1 failed"]
    assert "Traceback" not in result.stderr


def test_every_bad_member_is_reported_not_just_the_first(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(workdir / "bad.zip", [(f"m{i}.txt", BODY) for i in range(5)])
    for name in ("m1.txt", "m3.txt", "m4.txt"):
        flip_byte(path, data_offset(path, name) + 1)
    result = cli("test", str(path))
    assert result.returncode == 1
    assert [line.split(":")[0] for line in _failed(result)] == [
        "FAILED  m1.txt",
        "FAILED  m3.txt",
        "FAILED  m4.txt",
    ]
    assert result.stdout.splitlines()[-1] == "Tested 5 members: 3 failed"


def test_json_report_lists_failures_with_details(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(workdir / "bad.zip", [("ok.txt", BODY), ("bad.txt", BODY)])
    flip_byte(path, data_offset(path, "bad.txt") + 2)
    document = load_json(cli("test", "--json", str(path)), VerifyReport)
    assert document["ok"] is False
    assert (document["tested"], document["failed"]) == (2, 1)
    statuses = {m["name"]: m for m in document["members"]}
    assert statuses["ok.txt"] == {"name": "ok.txt", "status": "ok", "detail": None}
    assert statuses["bad.txt"]["status"] == "failed"
    detail = statuses["bad.txt"]["detail"]
    assert detail is not None
    assert "CRC" in detail


@pytest.mark.parametrize(
    "compression", [zipctl.ZIP_DEFLATED, zipctl.ZIP_BZIP2, zipctl.ZIP_LZMA]
)
def test_damaged_compressed_streams_are_reported_not_crashes(
    cli: CliRunner, workdir: Path, compression: int
) -> None:
    payload = bytes(range(256)) * 400
    path = write_archive(
        workdir / "c.zip", [("a.bin", payload)], compression=compression
    )
    start = data_offset(path, "a.bin")
    for offset in range(8, 40, 3):
        flip_byte(path, start + offset)
    result = cli("test", str(path))
    assert result.returncode == 1, result
    assert result.stdout.startswith("FAILED  a.bin: ")
    assert "Traceback" not in result.stderr


def test_truncated_member_data_is_reported(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(
        workdir / "t.zip", [("a.bin", bytes(range(256)) * 300)], compression=8
    )
    raw = path.read_bytes()
    central = raw.index(b"PK\x01\x02")
    # Claim a much larger compressed size than the archive holds.
    import struct

    struct.pack_into("<L", bytearray(raw), 0, 0)  # no-op guard to keep import used
    patched = bytearray(raw)
    struct.pack_into("<L", patched, central + 20, 10**6)
    path.write_bytes(bytes(patched))
    result = cli("test", str(path))
    assert result.returncode == 1, result
    assert "FAILED  a.bin" in result.stdout
    assert "Traceback" not in result.stderr


def test_unsupported_compression_method_is_reported(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(workdir / "u.zip", [("a.txt", BODY), ("b.txt", BODY)])
    set_compress_type(path, "a.txt", 98)  # PPMd, not implemented
    result = cli("test", str(path))
    assert result.returncode == 1, result
    (failure,) = _failed(result)
    assert failure.startswith("FAILED  a.txt: unsupported")
    assert "Traceback" not in result.stderr


def test_strong_encryption_flag_is_reported_as_unsupported(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(workdir / "s.zip", [("a.txt", BODY)])
    set_flag_bits(path, "a.txt", 1 << 6)
    result = cli("test", str(path))
    assert result.returncode == 1
    assert "unsupported" in result.stdout


def test_hostile_member_names_are_escaped_in_failure_lines(
    cli: CliRunner, workdir: Path
) -> None:
    name = "evil\x1b[31m\nname.txt"
    path = write_archive(workdir / "h.zip", [(name, BODY)])
    flip_byte(path, data_offset(path, name) + 3)
    result = cli("test", str(path))
    assert result.returncode == 1
    assert "\x1b" not in result.stdout
    assert len(_failed(result)) == 1
    assert "evil\\x1b[31m\\x0aname.txt" in result.stdout


# --- passwords from files, standard input and the environment ------------------


@pytest.fixture
def aes_archive(workdir: Path) -> Path:
    return write_archive(
        workdir / "aes.zip",
        [("secret.txt", BODY), ("more.txt", BODY)],
        encryption=zipctl.WZ_AES,
        password=PW,
    )


def _passfile(workdir: Path, content: bytes, name: str = "pw") -> Path:
    path = workdir / name
    path.write_bytes(content)
    return path


def test_encrypted_members_fail_without_a_password_and_say_how_to_supply_one(
    cli: CliRunner, aes_archive: Path
) -> None:
    result = cli("test", str(aes_archive))
    assert result.returncode == 1, result
    assert len(_failed(result)) == 2
    assert "password required" in result.stdout
    for hint in ("--password-file", "--password-stdin", "ZIPCTL_PASSWORD"):
        assert hint in result.stdout


def test_unencrypted_members_are_still_tested_when_others_need_a_password(
    cli: CliRunner, workdir: Path
) -> None:
    path = workdir / "mixed.zip"
    with ZipFile(path, "w") as zf:
        zf.setpassword(PW)
        zf.writestr("open.txt", BODY)
        zf.writestr("locked.txt", BODY, encryption=zipctl.WZ_AES)
    result = cli("test", "-v", str(path))
    assert "OK      open.txt" in result.stdout
    assert "FAILED  locked.txt: password required" in result.stdout
    assert result.returncode == 1


def test_password_file_may_hold_non_utf8_bytes(cli: CliRunner, workdir: Path) -> None:
    raw = b"\xff\xfe binary \x00 secret"
    path = write_archive(
        workdir / "bin.zip", [("s.txt", BODY)], encryption=zipctl.WZ_AES, password=raw
    )
    passfile = _passfile(workdir, raw + b"\n")
    assert cli("test", "--password-file", str(passfile), str(path)).returncode == 0


def test_password_from_stdin(cli: CliRunner, aes_archive: Path) -> None:
    result = cli("test", "--password-stdin", str(aes_archive), stdin=PASSWORD + "\n")
    assert result.returncode == 0, result
    result = cli("test", "--password-stdin", str(aes_archive), stdin=PASSWORD)
    assert result.returncode == 0, result


def test_password_from_the_environment(cli: CliRunner, aes_archive: Path) -> None:
    result = cli("test", str(aes_archive), env={"ZIPCTL_PASSWORD": PASSWORD})
    assert result.returncode == 0, result


def test_wrong_password_is_reported_as_wrong_not_as_corruption(
    cli: CliRunner, workdir: Path, aes_archive: Path
) -> None:
    passfile = _passfile(workdir, b"not the password\n")
    result = cli("test", "--password-file", str(passfile), str(aes_archive))
    assert result.returncode == 1
    assert result.stdout.count("wrong password") == 2
    assert "corrupt" not in result.stdout


def test_several_password_sources_are_all_tried(
    cli: CliRunner, workdir: Path, aes_archive: Path
) -> None:
    passfile = _passfile(workdir, b"decoy\n")
    result = cli(
        "test",
        "--password-file",
        str(passfile),
        "--password-stdin",
        str(aes_archive),
        stdin=PASSWORD + "\n",
    )
    assert result.returncode == 0, result


def test_per_member_passwords_are_matched_to_their_members(
    cli: CliRunner, workdir: Path
) -> None:
    path = workdir / "per.zip"
    with ZipFile(path, "w", encryption=zipctl.WZ_AES) as zf:
        zf.writestr("alpha.txt", BODY, password=b"alpha-pass")
        zf.writestr("beta.txt", BODY, password=b"beta-pass")
        zf.writestr("plain.txt", BODY, encryption=None)
    both = _passfile(workdir, b"alpha-pass\n", "one")
    result = cli(
        "test", "--password-file", str(both), "--password-stdin", str(path),
        stdin="beta-pass\n",
    )  # fmt: skip
    assert result.returncode == 0, result

    only_alpha = cli("test", "-v", "--password-file", str(both), str(path))
    assert only_alpha.returncode == 1
    assert "OK      alpha.txt" in only_alpha.stdout
    assert "FAILED  beta.txt: wrong password" in only_alpha.stdout
    assert "OK      plain.txt" in only_alpha.stdout


ENCRYPTED_FLAVOURS = [
    (zipctl.WZ_AES, zipctl.ZipFileExtra(wz_aes_nbits=128)),
    (zipctl.WZ_AES, zipctl.ZipFileExtra(wz_aes_nbits=192)),
    (zipctl.WZ_AES, zipctl.ZipFileExtra(wz_aes_nbits=256)),
    (zipctl.WZ_AES, zipctl.ZipFileExtra(force_wz_aes_version=1)),
    (zipctl.ZIP_CRYPTO, None),
]


@pytest.mark.parametrize(("encryption", "extra"), ENCRYPTED_FLAVOURS)
@pytest.mark.parametrize("compression", [zipctl.ZIP_STORED, zipctl.ZIP_DEFLATED])
def test_every_encryption_scheme_verifies_with_the_right_password(
    cli: CliRunner,
    workdir: Path,
    encryption: str,
    extra: zipctl.ZipFileExtra | None,
    compression: int,
) -> None:
    path = write_archive(
        workdir / "e.zip",
        [("a.txt", BODY), ("b.txt", BODY[:333])],
        compression=compression,
        encryption=encryption,
        password=PW,
        extra=extra,
    )
    result = cli("test", str(path), env={"ZIPCTL_PASSWORD": PASSWORD})
    assert result.returncode == 0, result
    assert result.stdout == "Tested 2 members: all OK\n"


@pytest.mark.parametrize(("encryption", "extra"), ENCRYPTED_FLAVOURS)
def test_tampered_encrypted_data_is_detected(
    cli: CliRunner, workdir: Path, encryption: str, extra: zipctl.ZipFileExtra | None
) -> None:
    path = write_archive(
        workdir / "e.zip",
        [("a.txt", BODY)],
        encryption=encryption,
        password=PW,
        extra=extra,
    )
    flip_byte(path, data_offset(path, "a.txt") + 30)
    result = cli("test", str(path), env={"ZIPCTL_PASSWORD": PASSWORD})
    assert result.returncode == 1, result
    (failure,) = _failed(result)
    assert "corrupt data, or the password is wrong" in failure


def test_encrypted_json_report_never_contains_the_password(
    cli: CliRunner, workdir: Path, aes_archive: Path
) -> None:
    passfile = _passfile(workdir, PW + b"\n")
    for extra in ([], ["--json"], ["-v"]):
        result = cli("test", *extra, "--password-file", str(passfile), str(aes_archive))
        assert PASSWORD not in result.stdout + result.stderr


# --- misconfiguration ----------------------------------------------------------


def test_prompting_without_a_terminal_is_a_usage_error(
    cli: CliRunner, aes_archive: Path
) -> None:
    result = cli("test", "--password-prompt", str(aes_archive))
    assert result.returncode == 2
    assert "needs a terminal" in result.stderr


def test_archives_without_encrypted_members_never_touch_password_sources(
    cli: CliRunner, workdir: Path
) -> None:
    """Even a bad password file must not matter when nothing is encrypted."""
    path = write_archive(workdir / "plain.zip", [("a.txt", BODY)])
    result = cli("test", str(path), env={"ZIPCTL_PASSWORD": "anything"})
    assert result.returncode == 0


def test_test_fails_cleanly_on_bad_archives(cli: CliRunner, workdir: Path) -> None:
    result = cli("test", str(workdir / "missing.zip"))
    assert result.returncode == 1
    assert "cannot open" in result.stderr
    junk = workdir / "junk.zip"
    junk.write_bytes(b"not a zip")
    result = cli("test", str(junk))
    assert result.returncode == 1
    assert "not a valid ZIP archive" in result.stderr


def test_summary_wording_for_a_single_member(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(workdir / "one.zip", [("a.txt", BODY)])
    assert cli("test", str(path)).stdout == "Tested 1 member: all OK\n"
    flip_byte(path, data_offset(path, "a.txt") + 4)
    assert cli("test", str(path)).stdout.splitlines()[-1] == "Tested 1 member: 1 failed"


# --- --quiet and --progress ---------------------------------------------------


def test_quiet_prints_nothing_when_every_member_passes(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(workdir / "ok.zip", [("a.txt", BODY)])
    result = cli("test", "-q", str(path))
    assert result.returncode == 0, result
    assert result.stdout == ""


def test_quiet_still_reports_failures(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(workdir / "bad.zip", [("good.txt", BODY), ("bad.txt", BODY)])
    flip_byte(path, data_offset(path, "bad.txt") + 5)
    result = cli("test", "-q", str(path))
    assert result.returncode == 1, result
    (failure,) = _failed(result)
    assert failure.startswith("FAILED  bad.txt: ")
    assert "OK" not in result.stdout


def test_quiet_and_verbose_exclude_each_other(cli: CliRunner, workdir: Path) -> None:
    result = cli("test", "-q", "-v", str(workdir / "x.zip"))
    assert result.returncode == 2, result


def test_progress_reports_each_member_on_standard_error(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(workdir / "bad.zip", [("good.txt", BODY), ("bad.txt", BODY)])
    flip_byte(path, data_offset(path, "bad.txt") + 5)
    result = cli("test", "--progress", str(path))
    assert result.returncode == 1, result
    assert result.stderr.splitlines() == [
        "[1/2] OK      good.txt",
        "[2/2] FAILED  bad.txt",
    ]
    assert "FAILED  bad.txt" in result.stdout


def test_without_progress_standard_error_stays_empty(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(workdir / "ok.zip", [("a.txt", BODY)])
    assert cli("test", str(path)).stderr == ""
