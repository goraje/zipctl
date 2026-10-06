"""Patterns for ``MEMBER`` on ``list`` and ``test``, and ``extract --match``."""

from __future__ import annotations

from pathlib import Path

import pytest

import zipctl
from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.support import PASSWORD, load_json, write_archive
from zipctl import ZipFile
from zipctl.cli.reports import ListReport


@pytest.fixture
def archive(workdir: Path) -> Path:
    return write_archive(
        workdir / "a.zip",
        [
            ("docs/a.md", b"a"),
            ("docs/deep/b.md", b"b"),
            ("src/main.py", b"m"),
            ("report[1].txt", b"r"),
            ("report1.txt", b"r1"),
        ],
    )


def test_list_takes_patterns(cli: CliRunner, archive: Path) -> None:
    result = cli("list", str(archive), "docs/*.md", "src/**")
    assert result.returncode == 0, result
    assert result.stdout.splitlines() == ["docs/a.md", "src/main.py"]


def test_list_a_literal_name_beats_the_pattern_reading(
    cli: CliRunner, archive: Path
) -> None:
    result = cli("list", str(archive), "report[1].txt")
    assert result.stdout.splitlines() == ["report[1].txt", "report1.txt"]


def test_list_json_and_footer_describe_the_selection(
    cli: CliRunner, archive: Path
) -> None:
    document = load_json(cli("list", str(archive), "docs/**", "--json"), ListReport)
    assert document["member_count"] == 2
    assert [m["name"] for m in document["members"]] == ["docs/a.md", "docs/deep/b.md"]
    long = cli("list", str(archive), "docs/**", "-l")
    assert "2 members, 2 B (" in long.stdout


def test_a_pattern_that_matches_nothing_is_an_error(
    cli: CliRunner, archive: Path
) -> None:
    for command in ("list", "test"):
        result = cli(command, str(archive), "docs/*.md", "nope*")
        assert result.returncode == 2, result
        assert "no member matches 'nope*'" in result.stderr
        assert result.stdout == ""


def test_a_malformed_pattern_is_a_usage_error(cli: CliRunner, archive: Path) -> None:
    result = cli("test", str(archive), "a**")
    assert result.returncode == 2, result
    assert "invalid pattern" in result.stderr


def test_test_checks_only_the_selected_members(cli: CliRunner, archive: Path) -> None:
    result = cli("test", str(archive), "src/**")
    assert result.returncode == 0, result
    assert result.stdout == "Tested 1 member: all OK\n"


def test_test_asks_for_passwords_only_for_the_selected_members(
    cli: CliRunner, workdir: Path
) -> None:
    path = workdir / "mixed.zip"
    with ZipFile(path, "w") as zf:
        zf.writestr("plain.txt", b"p")
        zf.writestr(
            "secret.txt",
            b"s",
            encryption=zipctl.WZ_AES,
            password=PASSWORD.encode(),
        )
    assert cli("test", str(path), "plain.txt").returncode == 0
    failing = cli("test", str(path), "secret.txt")
    assert failing.returncode == 1
    assert "password required" in failing.stdout


def test_extract_match_adds_patterns_to_the_named_members(
    cli: CliRunner, archive: Path, workdir: Path
) -> None:
    out = workdir / "out"
    result = cli(
        "extract", str(archive), "src/main.py", "--match", "docs/**", "-d", str(out)
    )
    assert result.returncode == 0, result
    found = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    assert found == ["docs/a.md", "docs/deep/b.md", "src/main.py"]


def test_extract_member_is_a_pattern_and_match_is_an_alias(
    cli: CliRunner, archive: Path, workdir: Path
) -> None:
    positional = cli("extract", str(archive), "docs/*.md", "-d", str(workdir / "one"))
    assert positional.returncode == 0, positional
    assert (workdir / "one" / "docs" / "a.md").exists()
    assert not (workdir / "one" / "docs" / "deep").exists()
    alias = cli(
        "extract", str(archive), "--match", "docs/*.md", "-d", str(workdir / "two")
    )
    assert alias.returncode == 0, alias
    assert (workdir / "two" / "docs" / "a.md").exists()
    literal = cli(
        "extract", str(archive), "report[1].txt", "-d", str(workdir / "three")
    )
    assert literal.returncode == 0, literal
    assert "report[1].txt" in {p.name for p in (workdir / "three").iterdir()}


def test_extract_match_dead_pattern_writes_nothing(
    cli: CliRunner, archive: Path, workdir: Path
) -> None:
    out = workdir / "out"
    result = cli("extract", str(archive), "--match", "nope*", "-d", str(out))
    assert result.returncode == 2, result
    assert "no member matches 'nope*'" in result.stderr
    assert not out.exists()
