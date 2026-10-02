"""Behaviour around the edges: encodings, environments, repeated runs."""

from __future__ import annotations

from pathlib import Path

import pytest

import zipctl
from tests.functional.cli.conftest import CliRunner, SubprocessRunner
from tests.functional.cli.reports import ErrorReport, ListReport, load_json
from tests.functional.cli.support import PASSWORD, data_offset, flip_byte, write_archive


def test_an_ascii_only_terminal_gets_escapes_instead_of_a_crash(
    cli_subprocess: SubprocessRunner, workdir: Path
) -> None:
    path = write_archive(workdir / "u.zip", [("café.txt", b"1")])
    result = cli_subprocess("list", str(path), env={"PYTHONIOENCODING": "ascii"})
    assert result.returncode == 0, result
    assert result.stdout == "caf\\xe9.txt\n"
    listing = cli_subprocess("list", "-l", str(path), env={"PYTHONIOENCODING": "ascii"})
    assert listing.returncode == 0
    assert "caf\\xe9.txt" in listing.stdout


def test_ascii_terminal_errors_are_escaped_too(
    cli_subprocess: SubprocessRunner, workdir: Path
) -> None:
    result = cli_subprocess(
        "list", str(workdir / "café.zip"), env={"PYTHONIOENCODING": "ascii"}
    )
    assert result.returncode == 1
    assert "caf\\xe9.zip" in result.stderr
    assert "Traceback" not in result.stderr


def test_json_is_ascii_whatever_the_terminal_encoding(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(workdir / "u.zip", [("\U0001f600日.txt", b"1")])
    for encoding in ("ascii", "utf-8", "latin-1"):
        result = cli("list", "--json", str(path), env={"PYTHONIOENCODING": encoding})
        assert result.returncode == 0, result
        assert result.stdout.isascii()
        member = load_json(result, ListReport)["members"][0]
        assert member["name"] == "\U0001f600日.txt"


def test_repeated_runs_give_identical_output(cli: CliRunner, workdir: Path) -> None:
    path = write_archive(
        workdir / "a.zip", [(f"f{i}.txt", bytes([i]) * 50) for i in range(20)]
    )
    for args in (["list", "-l"], ["list", "--json"], ["test", "-v"], ["inspect"]):
        outputs = {cli(*args, str(path)).stdout for _ in range(3)}
        assert len(outputs) == 1, args


def test_running_from_another_directory_with_relative_paths(
    cli: CliRunner, workdir: Path
) -> None:
    write_archive(workdir / "rel.zip", [("a.txt", b"1")])
    result = cli("list", "rel.zip", cwd=workdir)
    assert result.returncode == 0, result
    assert result.stdout == "a.txt\n"
    document = load_json(cli("list", "--json", "rel.zip", cwd=workdir), ListReport)
    assert document["archive"] == "rel.zip"


def test_paths_with_spaces_and_unicode(cli: CliRunner, workdir: Path) -> None:
    folder = workdir / "my archives é"
    folder.mkdir()
    path = write_archive(folder / "s p a c e.zip", [("a.txt", b"1")])
    assert cli("list", str(path)).stdout == "a.txt\n"
    assert cli("test", str(path)).returncode == 0
    assert cli("inspect", "-d", str(folder / "out"), str(path)).returncode == 0


def test_a_password_never_shows_up_in_any_output_stream(
    cli: CliRunner, workdir: Path
) -> None:
    path = write_archive(
        workdir / "e.zip",
        [("a.txt", b"payload" * 20)],
        encryption=zipctl.WZ_AES,
        password=PASSWORD.encode(),
    )
    flip_byte(path, data_offset(path, "a.txt") + 25)
    passfile = workdir / "pw"
    passfile.write_bytes(PASSWORD.encode() + b"\n")
    variants = [
        ["test", "--password-file", str(passfile), str(path)],
        ["test", "--json", "--password-file", str(passfile), str(path)],
        ["test", "-v", "--password-stdin", str(path)],
        ["test", "--password-file", str(workdir / "missing"), str(path)],
        ["test", "--password-stdin", str(path)],
    ]
    for args in variants:
        result = cli(*args, stdin=PASSWORD + "\n", env={"ZIPCTL_PASSWORD": PASSWORD})
        assert PASSWORD not in result.stdout + result.stderr, args


@pytest.mark.parametrize(
    ("args", "code"),
    [
        (["list", "@a"], 0),
        (["test", "@a"], 0),
        (["inspect", "@a"], 0),
        (["policy", "show"], 0),
        (["list", "@missing"], 1),
        (["test", "@missing"], 1),
        (["inspect", "@missing"], 1),
        (["list"], 2),
        (["policy", "validate", "@bad"], 2),
        (["inspect", "@a", "--policy-json", "{"], 2),
    ],
)
def test_exit_code_contract(
    cli: CliRunner, workdir: Path, args: list[str], code: int
) -> None:
    """0 success, 1 the operation failed, 2 usage or configuration."""
    archive = write_archive(workdir / "a.zip", [("a.txt", b"1")])
    bad = workdir / "bad.json"
    bad.write_text("{nope")
    values = {"@a": archive, "@missing": workdir / "missing.zip", "@bad": bad}
    resolved = [str(values.get(arg, arg)) for arg in args]
    result = cli(*resolved, cwd=workdir)
    assert result.returncode == code, result
    if code:
        assert "Traceback" not in result.stderr


def test_a_failure_under_json_is_a_document_on_standard_output(
    cli: CliRunner, workdir: Path
) -> None:
    result = cli("list", str(workdir / "missing.zip"), "--json")
    assert result.returncode == 1, result
    document = load_json(result, ErrorReport)
    assert document["ok"] is False
    assert document["code"] == 1
    assert "missing.zip" in document["error"]
    assert result.stderr.startswith("zipctl: error: ")
