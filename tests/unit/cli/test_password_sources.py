"""Where a password comes from: file, standard input, environment, prompt."""

from __future__ import annotations

import argparse
import io
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from typing_extensions import override

from tests.unit.cli.test_password_pool import FakeZip
from zipctl.cli.commands.helpers.passwords import (
    ENV_VAR,
    OLD_ENV_VAR,
    OldPasswordArgs,
    PasswordArgs,
    PasswordFamily,
    add_old_password_options,
    add_password_options,
    prompt_new_password,
    read_password_file,
    read_stdin_password,
    require_tty_for_prompt,
)
from zipctl.cli.context import Context, ask_terminal
from zipctl.cli.errors import EXIT_USAGE, UsageError
from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.info import WzAesExtra, ZipInfo


class _Terminal(io.StringIO):
    @override
    def isatty(self) -> bool:
        return True


def _ctx(
    stdin: str = "",
    env: dict[str, str] | None = None,
    *,
    tty: bool = False,
    prompt: Callable[[str], str] = ask_terminal,
) -> Context:
    stream = _Terminal(stdin) if tty else io.StringIO(stdin)
    return Context(stream, io.StringIO(), io.StringIO(), env or {}, prompt=prompt)


def _options(
    *, file: str | None = None, stdin: bool = False, prompt: bool = False
) -> PasswordFamily:
    return PasswordFamily(file, stdin, prompt)


def _member(name: str) -> ZipInfo:
    # an AES member: its verifier is trusted
    return ZipInfo(name, aes_extra=WzAesExtra(2, b"AE", 3))


def _password_file(tmp_path: Path, content: bytes) -> str:
    path = tmp_path / "pw"
    path.write_bytes(content)
    return str(path)


# -- password file -----------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "password"),
    [
        (b"secret\n", b"secret"),
        (b"secret\r\n", b"secret"),
        (b"secret", b"secret"),
        (b"first\nsecond\n", b"first"),
    ],
)
def test_password_file_gives_its_first_line(
    tmp_path: Path, content: bytes, password: bytes
) -> None:
    assert read_password_file(_password_file(tmp_path, content)) == password


@pytest.mark.parametrize("content", [b"", b"\n", b"\r\n"])
def test_empty_password_file_is_a_usage_error(tmp_path: Path, content: bytes) -> None:
    with pytest.raises(UsageError, match="is empty") as caught:
        read_password_file(_password_file(tmp_path, content))
    assert caught.value.code == EXIT_USAGE


def test_missing_password_file_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="cannot read password file"):
        read_password_file(str(tmp_path / "absent"))


# -- standard input ----------------------------------------------------------


def test_stdin_password_is_its_first_line() -> None:
    assert read_stdin_password(_ctx("secret\nrest\n")) == b"secret"


def test_empty_stdin_password_is_a_usage_error() -> None:
    with pytest.raises(UsageError, match="no password on standard input"):
        read_stdin_password(_ctx(""))


def test_stdin_password_refuses_a_terminal() -> None:
    with pytest.raises(UsageError, match="use --password-prompt"):
        read_stdin_password(_ctx("x\n", tty=True))


def test_old_stdin_password_refusal_does_not_suggest_the_prompt() -> None:
    with pytest.raises(UsageError, match="--old-password-stdin") as caught:
        read_stdin_password(_ctx("x\n", tty=True), old=True)
    assert "--password-prompt" not in caught.value.message


def test_standard_input_serves_only_one_purpose() -> None:
    ctx = _ctx("one\ntwo\n")
    read_stdin_password(ctx)
    with pytest.raises(UsageError, match="cannot be used for both"):
        read_stdin_password(ctx, old=True)


# -- static passwords --------------------------------------------------------


def test_static_passwords_fall_back_to_the_environment() -> None:
    ctx = _ctx(env={ENV_VAR: "from env"})
    assert PasswordFamily().given(ctx) == [b"from env"]


def test_static_passwords_ignore_the_environment_for_a_prompt() -> None:
    ctx = _ctx(env={ENV_VAR: "from env"})
    assert PasswordFamily(prompt=True).given(ctx) == []


def test_an_empty_environment_value_is_no_password() -> None:
    assert PasswordFamily().given(_ctx(env={ENV_VAR: ""})) == []


def test_the_old_password_reads_its_own_environment_variable() -> None:
    ctx = _ctx(env={ENV_VAR: "new", OLD_ENV_VAR: "old"})
    assert PasswordFamily(old=True).given(ctx) == [b"old"]


def test_a_file_beats_the_environment(tmp_path: Path) -> None:
    ctx = _ctx(env={ENV_VAR: "from env"})
    path = _password_file(tmp_path, b"from file\n")
    assert PasswordFamily(file=path).given(ctx) == [b"from file"]


def test_a_file_and_stdin_give_two_passwords(tmp_path: Path) -> None:
    path = _password_file(tmp_path, b"from file\n")
    ctx = _ctx("from stdin\n")
    assert PasswordFamily(file=path, stdin=True).given(ctx) == [
        b"from file",
        b"from stdin",
    ]


def test_the_same_password_from_two_sources_counts_once(tmp_path: Path) -> None:
    path = _password_file(tmp_path, b"same\n")
    assert PasswordFamily(file=path, stdin=True).given(_ctx("same\n")) == [b"same"]


def test_environment_password_keeps_undecodable_bytes() -> None:
    ctx = _ctx(env={ENV_VAR: "caf\udce9"})
    assert PasswordFamily().given(ctx) == [b"caf\xe9"]


# -- prompting for a new password -------------------------------------------


def test_new_password_needs_a_terminal() -> None:
    with pytest.raises(UsageError, match="no password given"):
        prompt_new_password("Password", _ctx())


def test_new_password_uses_the_hint_without_a_terminal() -> None:
    with pytest.raises(UsageError, match="say which"):
        prompt_new_password("Password", _ctx(), hint="say which")


def test_new_password_is_asked_twice() -> None:
    asked: list[str] = []
    answers = iter(["hunter2", "hunter2"])

    def prompt(label: str) -> str:
        asked.append(label)
        return next(answers)

    password = prompt_new_password("Password for a/**", _ctx(tty=True, prompt=prompt))
    assert password == b"hunter2"
    assert asked == ["Password for a/**: ", "Confirm password for a/**: "]


def test_new_password_must_be_confirmed() -> None:
    answers = iter(["one", "two"])
    with pytest.raises(UsageError, match="do not match"):
        prompt_new_password(
            "Password", _ctx(tty=True, prompt=lambda _label: next(answers))
        )


def test_an_empty_new_password_is_refused() -> None:
    with pytest.raises(UsageError, match="no password entered"):
        prompt_new_password("Password", _ctx(tty=True, prompt=lambda _label: ""))


def test_prompt_option_needs_a_terminal() -> None:
    with pytest.raises(UsageError, match="--password-prompt needs a terminal"):
        require_tty_for_prompt(_ctx())


# -- the options and the one password they name ------------------------------


def _password_args(args: argparse.Namespace) -> PasswordArgs:
    return cast("PasswordArgs", args)  # pyright: ignore[reportInvalidCast]  # Namespace has the attributes the Protocol names


def _old_password_args(args: argparse.Namespace) -> OldPasswordArgs:
    return cast("OldPasswordArgs", args)  # pyright: ignore[reportInvalidCast]  # Namespace has the attributes the Protocol names


def test_options_are_read_from_parsed_arguments() -> None:
    parser = argparse.ArgumentParser()
    add_password_options(parser)
    args = parser.parse_args(["--password-file", "f", "--password-stdin"])
    assert PasswordFamily.from_args(_password_args(args)) == PasswordFamily(
        "f", True, False
    )
    assert PasswordFamily.from_args(
        _password_args(parser.parse_args([]))
    ) == PasswordFamily(None, False, False)


def test_old_password_options_feed_the_old_pool(tmp_path: Path) -> None:
    parser = argparse.ArgumentParser()
    add_old_password_options(parser)
    path = _password_file(tmp_path, b"old one\n")
    args = parser.parse_args(["--old-password-file", path])
    ctx = _ctx(env={ENV_VAR: "new", OLD_ENV_VAR: "ignored"})
    pool = PasswordFamily.old_from_args(_old_password_args(args)).pool(ctx)
    zf = FakeZip({"a": b"old one"})
    archive = cast(ZipFile, zf)  # pyright: ignore[reportInvalidCast]  # duck-typed stand-in
    assert pool.resolve(archive, _member("a")) == b"old one"
    assert zf.checked == [b"old one"]


def test_given_password_is_none_when_nothing_is_given() -> None:
    assert _options().given_one(_ctx()) is None


def test_given_password_comes_from_the_environment() -> None:
    assert _options().given_one(_ctx(env={ENV_VAR: "env"})) == b"env"


def test_given_password_refuses_two_different_ones(tmp_path: Path) -> None:
    path = _password_file(tmp_path, b"one\n")
    with pytest.raises(UsageError, match="this command uses one password"):
        _options(file=path, stdin=True).given_one(_ctx("two\n"))


def test_single_password_prefers_a_given_one() -> None:
    def prompt(_label: str) -> str:
        raise AssertionError("must not prompt")

    ctx = _ctx(env={ENV_VAR: "env"}, tty=True, prompt=prompt)
    assert _options().ask_one(ctx) == b"env"


def test_single_password_refuses_two_different_ones(tmp_path: Path) -> None:
    path = _password_file(tmp_path, b"one\n")
    with pytest.raises(UsageError, match="this command tests one password"):
        _options(file=path, stdin=True).ask_one(_ctx("two\n"))


def test_single_password_without_source_or_terminal_lists_the_ways() -> None:
    with pytest.raises(UsageError, match="no password given"):
        _options().ask_one(_ctx())


def test_single_password_prompt_without_terminal_names_the_prompt() -> None:
    with pytest.raises(UsageError, match="--password-prompt needs a terminal"):
        _options(prompt=True).ask_one(_ctx())


def test_single_password_is_prompted_for_at_a_terminal() -> None:
    asked: list[str] = []

    def prompt(label: str) -> str:
        asked.append(label)
        return "typed"

    assert _options().ask_one(_ctx(tty=True, prompt=prompt)) == b"typed"
    assert asked == ["Password: "]


def test_single_password_prompt_ignores_the_environment() -> None:
    ctx = _ctx(env={ENV_VAR: "env"}, tty=True, prompt=lambda _label: "typed")
    assert _options(prompt=True).ask_one(ctx) == b"typed"


def test_single_password_refuses_an_empty_answer() -> None:
    with pytest.raises(UsageError, match="no password entered"):
        _options().ask_one(_ctx(tty=True, prompt=lambda _label: ""))


def test_a_password_file_loses_a_utf8_byte_order_mark(tmp_path: Path) -> None:
    path = tmp_path / "pw"
    path.write_bytes(b"\xef\xbb\xbfsecret\r\n")
    assert read_password_file(str(path)) == b"secret"


def test_a_utf16_password_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "pw"
    path.write_text("secret\n", encoding="utf-16")
    with pytest.raises(UsageError, match="UTF-16"):
        read_password_file(str(path))
