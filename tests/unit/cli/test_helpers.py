"""Pure helpers of the command-line interface."""

from __future__ import annotations

import argparse
import io
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath

import pytest

from tests.unit.cli.conftest import new_context
from ziplet.cli.commands.helpers.output_options import (
    OutputOptions,
    add_output_options,
)
from ziplet.cli.commands.helpers.progress import _columns, _shorten
from ziplet.cli.commands.helpers.selection import glob_matcher
from ziplet.cli.context import Context
from ziplet.cli.errors import EXIT_USAGE, CliError, UsageError
from ziplet.cli.output import count, format_table, human_size, printable, to_jsonable


@pytest.mark.parametrize(
    ("size", "text"),
    [
        (0, "0 B"),
        (1023, "1023 B"),
        (1024, "1.0 KiB"),
        (1536, "1.5 KiB"),
        (1024 * 1024 - 1, "1.0 MiB"),  # not "1024.0 KiB"
        (1024**3, "1.0 GiB"),
        (5 * 1024**4, "5.0 TiB"),
        (2048 * 1024**4, "2048.0 TiB"),
    ],
)
def test_human_size(size: int, text: str) -> None:
    assert human_size(size) == text


def test_format_table_aligns_and_leaves_a_left_last_column_unpadded() -> None:
    lines = format_table(["N", "Name"], [["1", "a"], ["22", "bb"]], right_aligned=(0,))
    assert lines == [" N  NAME", " 1  a", "22  bb"]


def test_format_table_can_right_align_the_last_column() -> None:
    lines = format_table(["Name", "N"], [["a", "1"], ["b", "22"]], right_aligned=(1,))
    assert lines == ["NAME   N", "a      1", "b     22"]


@pytest.mark.parametrize("pattern", ["a**", "[z-a]", "x/**y"])
def test_a_malformed_glob_is_a_usage_error(pattern: str) -> None:
    with pytest.raises(CliError) as caught:
        glob_matcher(pattern)
    assert caught.value.code == 2
    assert "invalid pattern" in caught.value.message


def test_a_glob_still_matches_the_name_written_literally() -> None:
    assert glob_matcher("report[1].txt")("report[1].txt")
    assert glob_matcher("**/*.py")("a/b/c.py")


def test_wide_characters_count_two_columns() -> None:
    assert _columns("abc") == 3
    assert _columns("日本語") == 6


def test_shorten_respects_the_width_of_wide_characters() -> None:
    name = "日本語" * 10
    for width in (5, 8, 20, 21, 59):
        assert _columns(_shorten(name, width)) <= width
    assert _shorten("short", 20) == "short"
    assert _columns(_shorten("x" * 50, 20)) == 20


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("plain name.txt", "plain name.txt"),
        ("ünïcode-日本.txt", "ünïcode-日本.txt"),
        ("a\nb", "a\\x0ab"),
        ("\x1b[31mred", "\\x1b[31mred"),
        ("rtl‮evil", "rtl\\u202eevil"),
        ("\U000e0041", "\\U000e0041"),
    ],
)
def test_printable_escapes_what_must_not_reach_a_terminal(
    text: str, shown: str
) -> None:
    assert printable(text) == shown


def test_printable_returns_safe_text_unchanged() -> None:
    text = "src/café ☃.txt"
    assert printable(text) is text


def test_count_picks_the_noun_form() -> None:
    assert count(1, "member") == "1 member"
    assert count(0, "member") == "0 members"
    assert count(2, "directory", "directories") == "2 directories"
    assert count(1, "directory", "directories") == "1 directory"


def test_to_jsonable_turns_rich_values_into_plain_data() -> None:
    @dataclass
    class Item:
        path: PurePosixPath
        kind: Kind
        tags: frozenset[str]

    class Kind(Enum):
        A = "a"

    value = Item(PurePosixPath("x/y"), Kind.A, frozenset({"b", "a"}))
    assert to_jsonable({"items": (value,)}) == {
        "items": [{"path": "x/y", "kind": "a", "tags": ["a", "b"]}]
    }


def test_a_usage_error_is_a_cli_error_with_the_usage_code() -> None:
    error = UsageError("bad", ("detail",))
    assert isinstance(error, CliError)
    assert (error.message, error.code, error.details) == (
        "bad",
        EXIT_USAGE,
        ("detail",),
    )


@pytest.mark.parametrize("line", [False, True])
def test_standard_input_reads_the_same_with_or_without_a_binary_buffer(
    line: bool,
) -> None:
    text = "first é\nsecond\n"
    wrapped = io.TextIOWrapper(io.BytesIO(text.encode()), encoding="utf-8")
    plain = new_context(stdin=text)
    binary = Context(wrapped, io.StringIO(), io.StringIO(), {})
    expected = b"first \xc3\xa9\n" if line else text.encode()
    assert plain.read_stdin(line=line) == expected
    assert binary.read_stdin(line=line) == expected


def test_a_warning_carries_the_program_prefix() -> None:
    err = io.StringIO()
    Context(io.StringIO(), io.StringIO(), err, {}).warn("careful")
    assert err.getvalue() == "ziplet: warning: careful\n"


def test_output_options_read_false_for_the_flags_a_command_lacks() -> None:
    parser = argparse.ArgumentParser()
    add_output_options(parser)  # only --json
    assert OutputOptions.from_args(parser.parse_args(["--json"])) == OutputOptions(
        json=True
    )
    parser = argparse.ArgumentParser()
    add_output_options(parser, verbose_help="more", quiet=True)
    parsed = parser.parse_args(["-v"])
    assert OutputOptions.from_args(parsed) == OutputOptions(verbose=True)
