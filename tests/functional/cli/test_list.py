"""``zipctl list``: names, the long table, JSON, and failure modes."""

from __future__ import annotations

import subprocess
import zlib
from pathlib import Path
from typing import cast

import pytest

import zipctl
from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.reports import ListReport, load_json
from tests.functional.cli.support import (
    clean_env,
    command,
    special_info,
    write_archive,
)
from zipctl import ZipFile
from zipctl.cli.output import human_size
from zipctl.compression import registry
from zipctl.zipfile.info import ZipInfo

DATA = b"hello zipctl " * 50


@pytest.fixture
def archive(workdir: Path) -> Path:
    path = workdir / "sample.zip"
    with ZipFile(path, "w", compression=zipctl.ZIP_DEFLATED) as zf:
        zf.mkdir("docs")
        zf.writestr("docs/readme.txt", DATA)
        zf.writestr("data.bin", bytes(range(256)) * 4)
        zf.writestr("empty.txt", b"")
    return path


def test_default_output_is_one_name_per_line_in_archive_order(
    cli: CliRunner, archive: Path
) -> None:
    result = cli("list", str(archive))
    assert result.returncode == 0, result
    assert result.stdout == "docs/\ndocs/readme.txt\ndata.bin\nempty.txt\n"
    assert result.stderr == ""


def test_unicode_names_are_printed_as_is(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(workdir / "u.zip", [("café.txt", b"1"), ("日本/語.txt", b"2")])
    assert cli("list", str(path)).stdout == "café.txt\n日本/語.txt\n"


HOSTILE = [
    "evil\x1b[31mred\x1b[0m.txt",
    "line1\nline2.txt",
    "bell\x07.txt",
    "nul\x00tail.txt",
    "tab\there.txt",
    "bidi‮gnp.exe",
]


@pytest.mark.parametrize("mode", [[], ["-l"]])
def test_hostile_names_are_escaped_so_they_cannot_drive_the_terminal(
    cli: CliRunner, workdir: Path, mode: list[str]
) -> None:
    path = write_archive(workdir / "h.zip", [(name, b"x") for name in HOSTILE])
    result = cli("list", *mode, str(path))
    assert result.returncode == 0, result
    for forbidden in ("\x1b", "\x07", "\t", "‮", "\x00"):
        assert forbidden not in result.stdout, repr(forbidden)
    assert "evil\\x1b[31mred\\x1b[0m.txt" in result.stdout
    assert "line1\\x0aline2.txt" in result.stdout
    assert "bidi\\u202egnp.exe" in result.stdout
    # A newline in a name must not fake an extra entry.
    first_columns = [line for line in result.stdout.splitlines() if "line2" in line]
    assert len(first_columns) == 1


def test_long_listing_shows_sizes_method_encryption_and_crc(
    cli: CliRunner, archive: Path
) -> None:
    result = cli("list", "-l", str(archive))
    assert result.returncode == 0, result
    lines = result.stdout.splitlines()
    header = lines[0].split()
    assert header[:4] == ["MODE", "LENGTH", "COMPRESSED", "SAVED"]
    assert header[-2:] == ["CRC-32", "NAME"]
    rows = {line.split()[-1]: line.split() for line in lines[1:-2]}
    readme = rows["docs/readme.txt"]
    assert readme[1] == str(len(DATA))
    assert int(readme[2]) < len(DATA)
    assert readme[3] == f"{round(100 * (1 - int(readme[2]) / len(DATA)))}%"
    assert "deflate" in readme
    assert "ENCRYPTION" not in header  # only shown when a member is encrypted
    assert f"{zlib.crc32(DATA):08x}" in readme
    assert rows["empty.txt"][1] == "0"
    assert rows["empty.txt"][3] == "-"
    assert lines[-1].startswith(f"4 members, {human_size(len(DATA) + 1024)} (")
    assert " compressed, " in lines[-1]


def test_long_listing_shows_the_stored_mode(cli: CliRunner, workdir: Path) -> None:
    info = ZipInfo("run.sh")
    info.external_attr = 0o100755 << 16
    path = workdir / "m.zip"
    with ZipFile(path, "w") as zf:
        zf.writestr(info, b"#!/bin/sh\n")
        zf.writestr("plain.txt", b"x")
    rows = cli("list", "-l", str(path)).stdout.splitlines()
    assert rows[1].split()[0] == "-rwxr-xr-x"
    assert rows[2].split()[0] == "-rw-------"  # the library's default mode


def test_long_listing_ends_with_the_archive_comment(
    cli: CliRunner, workdir: Path
) -> None:
    path = workdir / "c.zip"
    with ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"x")
        zf.comment = b"first line\nsecond \x1b[31mred"
    lines = cli("list", "-l", str(path)).stdout.splitlines()
    assert lines[-3:] == ["Comment:", "  first line", "  second \\x1b[31mred"]
    plain = write_archive(workdir / "p.zip", [("a.txt", b"x")])
    assert "Comment:" not in cli("list", "-l", str(plain)).stdout


def test_long_listing_shows_the_encryption_column_only_for_encrypted_archives(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(
        workdir / "e.zip",
        [("s.txt", DATA)],
        encryption=zipctl.WZ_AES,
        password=b"pw",
    )
    lines = cli("list", "-l", str(path)).stdout.splitlines()
    assert lines[0].split()[-3:] == ["ENCRYPTION", "CRC-32", "NAME"]
    assert "AES-256" in lines[1]


@pytest.mark.parametrize(
    ("version", "crc"), [(zipctl.WZ_AES_V1, "00000000"), (zipctl.WZ_AES_V2, "-")]
)
def test_long_listing_hides_the_crc_only_where_aes_2_does_not_store_it(
    cli: CliRunner, workdir: Path, version: int, crc: str
) -> None:
    path = write_archive(
        workdir / "e.zip",
        [("empty.txt", b"")],  # its real CRC-32 is 0, which is not "hidden"
        encryption=zipctl.WZ_AES,
        password=b"pw",
        extra=zipctl.ZipFileExtra(force_wz_aes_version=version),
    )
    row = cli("list", "-l", str(path)).stdout.splitlines()[1]
    assert row.split()[-2] == crc


def test_long_listing_separates_table_footer_and_comment_with_empty_lines(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(workdir / "c.zip", [("a.txt", b"x")], comment=b"hi")
    lines = cli("list", "-l", str(path)).stdout.splitlines()
    assert [line == "" for line in lines] == [
        False,
        False,
        True,
        False,
        True,
        False,
        False,
    ]
    assert lines[-2:] == ["Comment:", "  hi"]


def test_long_listing_columns_line_up(cli: CliRunner, archive: Path) -> None:
    lines = cli("list", "-l", str(archive)).stdout.splitlines()[:-2]
    name_column = lines[0].index("NAME")
    for line in lines[1:]:
        assert line[name_column - 2 : name_column] == "  "
        assert line[name_column] != " "


COMPRESSIONS = [
    (zipctl.ZIP_STORED, "store"),
    (zipctl.ZIP_DEFLATED, "deflate"),
    (zipctl.ZIP_BZIP2, "bzip2"),
    (zipctl.ZIP_LZMA, "lzma"),
    pytest.param(
        zipctl.ZIP_ZSTANDARD,
        "zstd",
        marks=pytest.mark.skipif(
            registry._registry.get(zipctl.ZIP_ZSTANDARD) is None,
            reason="zstd is not available",
        ),
    ),
]


@pytest.mark.parametrize(("compression", "label"), COMPRESSIONS)
def test_every_compression_method_is_named(
    cli: CliRunner, workdir: Path, compression: int, label: str
) -> None:
    path = write_archive(workdir / "c.zip", [("f.txt", DATA)], compression=compression)
    assert label in cli("list", "-l", str(path)).stdout.splitlines()[1].split()
    record = load_json(cli("list", "--json", str(path)), ListReport)["members"][0]
    assert record["compression"] == label


ENCRYPTIONS = [
    (zipctl.WZ_AES, zipctl.ZipFileExtra(wz_aes_nbits=128), "AES-128"),
    (zipctl.WZ_AES, zipctl.ZipFileExtra(wz_aes_nbits=192), "AES-192"),
    (zipctl.WZ_AES, zipctl.ZipFileExtra(wz_aes_nbits=256), "AES-256"),
    (zipctl.WZ_AES, zipctl.ZipFileExtra(force_wz_aes_version=1), "AES-256"),
    (zipctl.ZIP_CRYPTO, None, "ZipCrypto"),
]


@pytest.mark.parametrize(("encryption", "extra", "label"), ENCRYPTIONS)
def test_every_encryption_scheme_is_named_without_needing_a_password(
    cli: CliRunner,
    workdir: Path,
    encryption: str,
    extra: zipctl.ZipFileExtra | None,
    label: str,
) -> None:
    path = write_archive(
        workdir / "e.zip",
        [("secret.txt", DATA)],
        encryption=encryption,
        password=b"pw",
        extra=extra,
    )
    result = cli("list", "-l", str(path))
    assert result.returncode == 0, result
    assert label in result.stdout.splitlines()[1].split()
    assert (
        load_json(cli("list", "--json", str(path)), ListReport)["members"][0][
            "encryption"
        ]
        == label
    )


def test_compression_inside_an_aes_entry_is_reported_not_the_aes_marker(
    cli: CliRunner, workdir: Path
) -> None:
    """WinZip AES stores method 99; the real method lives in the extra field."""
    path = write_archive(
        workdir / "e.zip",
        [("s.txt", DATA)],
        compression=zipctl.ZIP_DEFLATED,
        encryption=zipctl.WZ_AES,
        password=b"pw",
    )
    record = load_json(cli("list", "--json", str(path)), ListReport)["members"][0]
    assert record["compression"] == "deflate"
    assert record["encryption"] == "AES-256"


def test_json_describes_the_archive_and_every_member(
    cli: CliRunner, workdir: Path
) -> None:
    link = special_info("link", 0o120777)
    path = workdir / "j.zip"
    with ZipFile(path, "w") as zf:
        zf.comment = b"archive comment \xc3\xa9"
        zf.mkdir("d")
        zf.writestr("d/file.txt", DATA)
        zf.writestr(link, b"d/file.txt")
        info = ZipInfo("m.txt", (2024, 5, 17, 13, 45, 58))
        info.external_attr = 0o100640 << 16
        info.comment = b"member note"
        zf.writestr(info, b"body")

    result = cli("list", "--json", str(path))
    assert result.returncode == 0, result
    document = load_json(result, ListReport)
    assert document["archive"] == str(path)
    assert document["comment"] == "archive comment é"
    assert document["member_count"] == 4
    by_name = {member["name"]: member for member in document["members"]}
    assert set(by_name) == {"d/", "d/file.txt", "link", "m.txt"}

    assert by_name["d/"]["directory"] is True
    assert by_name["d/file.txt"]["directory"] is False
    assert by_name["link"]["is_symlink"] is True
    assert by_name["d/file.txt"]["is_symlink"] is False
    member = by_name["m.txt"]
    assert member["modified"] == "2024-05-17T13:45:58"
    assert member["mode"] == "100640"
    assert member["comment"] == "member note"
    assert member["size"] == 4
    assert member["compressed_size"] == 4
    assert member["crc32"] == f"{zlib.crc32(b'body'):08x}"
    assert member["compression"] == "store"
    assert member["encryption"] == "none"
    assert set(member) == {
        "name", "directory", "is_symlink", "size",
        "compressed_size", "modified", "compression", "encryption", "crc32",
        "mode", "comment",
    }  # fmt: skip


def test_saved_is_the_share_compression_removed(cli: CliRunner, workdir: Path) -> None:
    path = workdir / "s.zip"
    with ZipFile(path, "w") as zf:
        zf.writestr("stored.txt", b"x" * 100, compress_type=zipctl.ZIP_STORED)
    rows = cli("list", "-l", str(path)).stdout.splitlines()
    assert rows[1].split()[3] == "0%"
    assert load_json(cli("list", "--json", str(path)), ListReport)["ok"] is True


def test_json_keeps_hostile_names_exactly_and_is_pure_ascii(
    cli: CliRunner, workdir: Path
) -> None:
    names = [*HOSTILE, "café", "\U0001f600.txt"]
    path = write_archive(workdir / "h.zip", [(name, b"x") for name in names])
    result = cli("list", "--json", str(path))
    assert result.returncode == 0, result
    assert result.stdout.isascii()
    listed = [member["name"] for member in load_json(result, ListReport)["members"]]
    # ZipInfo ends a name at its first NUL byte; everything else survives.
    assert listed == [name.split("\x00")[0] for name in names]


def test_empty_archive(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(workdir / "empty.zip", [])
    assert cli("list", str(path)).stdout == ""
    assert cli("list", str(path)).returncode == 0
    assert cli("list", "-l", str(path)).stdout.splitlines()[-1] == "0 members, 0 B"
    assert load_json(cli("list", "--json", str(path)), ListReport)["member_count"] == 0


def test_archive_with_prepended_data_is_listed(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(workdir / "sfx.zip", [("a.txt", b"a")])
    path.write_bytes(b"#!/bin/sh\nexit 0\n" * 20 + path.read_bytes())
    assert cli("list", str(path)).stdout == "a.txt\n"


def test_large_archives_are_listed_completely(cli: CliRunner, workdir: Path) -> None:
    names = [f"dir{i % 7}/file{i:05d}.txt" for i in range(3000)]
    path = write_archive(workdir / "big.zip", [(name, b"") for name in names])
    assert cli("list", str(path)).stdout.splitlines() == names


def test_the_archive_is_never_modified(cli: CliRunner, archive: Path) -> None:
    before = archive.read_bytes()
    for args in (["list"], ["list", "-l"], ["list", "--json"]):
        assert cli(*args, str(archive)).returncode == 0
    assert archive.read_bytes() == before


# --- failures ---------------------------------------------------------------


def test_missing_archive(cli: CliRunner, workdir: Path) -> None:
    result = cli("list", str(workdir / "nope.zip"))
    assert result.returncode == 1
    assert result.stdout == ""
    assert "zipctl: error: cannot open" in result.stderr
    assert "nope.zip" in result.stderr
    assert "Traceback" not in result.stderr


def test_directory_instead_of_archive(cli: CliRunner, workdir: Path) -> None:
    result = cli("list", str(workdir))
    assert result.returncode == 1
    assert "zipctl: error: cannot open" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "content", [b"", b"just some text, not a zip", b"PK\x03\x04" + b"\x00" * 10]
)
def test_files_that_are_not_zip_archives(
    cli: CliRunner, workdir: Path, content: bytes
) -> None:
    path = workdir / "notzip.zip"
    path.write_bytes(content)
    result = cli("list", str(path))
    assert result.returncode == 1
    assert "not a valid ZIP archive" in result.stderr
    assert "Traceback" not in result.stderr


def test_truncated_archive(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(workdir / "t.zip", [("a.txt", DATA), ("b.txt", DATA)])
    path.write_bytes(path.read_bytes()[:-30])
    result = cli("list", str(path))
    assert result.returncode == 1
    assert "not a valid ZIP archive" in result.stderr


def test_errors_never_leak_control_characters_from_the_path(
    cli: CliRunner, workdir: Path
) -> None:
    result = cli("list", str(workdir / "bad\x1b[31mname.zip"))
    assert result.returncode == 1
    assert "\x1b" not in result.stderr
    assert "bad\\x1b[31mname.zip" in result.stderr


def test_a_closed_output_pipe_is_a_quiet_exit_not_a_traceback(
    workdir: Path,
) -> None:
    names = [f"a/rather/long/directory/name/{i:06d}.txt" for i in range(6000)]
    path = write_archive(workdir / "big.zip", [(name, b"") for name in names])
    proc: subprocess.Popen[bytes] = subprocess.Popen(
        command("list", str(path)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=clean_env(),
    )
    assert proc.stdout is not None
    first_line = cast(bytes, cast(object, proc.stdout.readline()))
    assert first_line.rstrip(b"\r\n") == names[0].encode()
    proc.stdout.close()
    stderr = proc.stderr.read() if proc.stderr else b""
    assert proc.wait(timeout=60) == 141, stderr
    assert stderr == b""


def test_counts_use_singular_and_plural_wording(cli: CliRunner, workdir: Path) -> None:
    one = write_archive(workdir / "one.zip", [("a.txt", b"x")])
    footer = cli("list", "-l", str(one)).stdout.splitlines()[-1]
    assert footer.startswith("1 member, 1 B (")
    two = write_archive(workdir / "two.zip", [("a.txt", b"xy"), ("b.txt", b"")])
    footer = cli("list", "-l", str(two)).stdout.splitlines()[-1]
    assert footer.startswith("2 members, 2 B (")
