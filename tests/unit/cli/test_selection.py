"""Choosing members and turning command-line paths into archive names."""

from __future__ import annotations

import pytest

from zipctl.cli.commands.helpers.collect import _arcname, _stored_name
from zipctl.cli.commands.helpers.selection import glob_matcher, select
from zipctl.cli.errors import CliError

NAMES = ["a.txt", "b.txt", "src/c.py", "src/d.py", "report[1].txt", "report1.txt"]


def test_no_patterns_selects_every_name() -> None:
    assert select(NAMES, [], "member") == set(NAMES)


def test_patterns_are_unioned() -> None:
    assert select(NAMES, ["*.txt", "src/*.py"], "member") == set(NAMES)
    assert select(NAMES, ["a.txt", "src/c.py"], "member") == {"a.txt", "src/c.py"}


def test_a_literal_name_beats_the_glob_reading() -> None:
    # 'report[1].txt' as a glob would be report1.txt, yet naming it still works
    assert "report[1].txt" in select(NAMES, ["report[1].txt"], "member")


@pytest.mark.parametrize(
    "pattern", ["docs", "docs/", "a.b", "a+b", "docs//", "", "x y", "back\\slash", "]"]
)
def test_a_plain_name_selects_what_its_glob_would_and_what_is_under_it(
    pattern: str,
) -> None:
    """The lookup for plain names must agree with matching them as a glob."""
    names = ["docs", "docs/", "docs//", "a.b", "aXb", "a+b", "", "/", "x y"]
    names += ["docs/x", "back\\slash", "]", "]/"]
    expected = {n for n in names if glob_matcher(pattern)(n)}
    if directory := pattern.rstrip("/"):
        expected |= {n for n in names if n.startswith(directory + "/")}
    if expected:
        assert select(names, [pattern], "member") == expected


@pytest.mark.parametrize("pattern", ["src", "src/"])
def test_a_directory_name_picks_everything_under_it(pattern: str) -> None:
    names = ["src/", "src/a.py", "src/sub/b.py", "srcx/c.py", "other/src/d.py", "z"]
    assert select(names, [pattern], "member") == {"src/", "src/a.py", "src/sub/b.py"}


def test_a_directory_without_its_own_entry_is_still_picked() -> None:
    assert select(["src/a.py", "b.py"], ["src"], "member") == {"src/a.py"}


def test_every_pattern_that_matches_nothing_is_reported() -> None:
    with pytest.raises(CliError) as caught:
        select(NAMES, ["*.txt", "nope", "*.md"], "member")
    assert caught.value.message == "no member matches 'nope', '*.md'"


def test_a_misspelt_plain_name_suggests_the_closest_member() -> None:
    with pytest.raises(CliError) as caught:
        select(NAMES, ["src/c.pyy", "z*"], "member")
    assert (
        caught.value.message
        == "no member matches 'src/c.pyy' (did you mean 'src/c.py'?), 'z*'"
    )


@pytest.mark.parametrize(
    ("given", "name"),
    [
        ("a.txt", "a.txt"),
        ("./a.txt", "a.txt"),
        ("d//sub/../a.txt", "d/a.txt"),
        ("/abs/a.txt", "abs/a.txt"),
        (".", ""),
        ("d/", "d"),
    ],
)
def test_arcname_gives_a_relative_normalised_name(given: str, name: str) -> None:
    assert _arcname(given) == name


@pytest.mark.parametrize("given", ["..", "../a.txt", "d/../../a.txt"])
def test_arcname_refuses_a_path_that_escapes(given: str) -> None:
    with pytest.raises(CliError, match="outside the current directory"):
        _arcname(given)


def test_stored_name_refuses_what_utf8_cannot_hold() -> None:
    assert _stored_name("ok-é.txt") == "ok-é.txt"
    with pytest.raises(CliError, match="not valid UTF-8"):
        _stored_name("bad\udcff.txt")
