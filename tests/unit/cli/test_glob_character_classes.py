"""Shell-compatible character classes for CLI member selection."""

import fnmatch

import pytest

from zipctl.cli.commands.helpers.selection import glob_matcher


@pytest.mark.parametrize(
    "pattern", ["[!a].txt", "[]a].txt", "[[]x.txt", "[a-c].txt", "[^a].txt"]
)
def test_shell_character_classes_match_fnmatch(pattern: str) -> None:
    matches = glob_matcher(pattern)
    for name in ["a.txt", "b.txt", "!.txt", "].txt", "[x.txt", "^.txt"]:
        assert matches(name) == fnmatch.fnmatchcase(name, pattern)
    assert not matches("/.txt")
