"""The CLI's contract as a program: help, version, usage errors, exit codes."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path
from typing import cast

import pytest

from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.support import Result, clean_env, write_archive
from ziplet.cli.parser import build_parser

COMMANDS = ["list", "test", "inspect", "policy"]


def test_help_lists_every_command(cli: CliRunner) -> None:
    result = cli("--help")
    assert result.returncode == 0, result
    for name in COMMANDS:
        assert name in result.stdout
    assert "--exit-codes" in result.stdout
    assert result.stderr == ""


def test_exit_codes_option_prints_the_table(cli: CliRunner) -> None:
    result = cli("--exit-codes")
    assert result.returncode == 0, result
    for code in ("0", "1", "2", "130", "141"):
        assert any(line.split()[:1] == [code] for line in result.stdout.splitlines())
    assert result.stderr == ""


@pytest.mark.parametrize(
    "command",
    [
        *["create", "list", "test", "inspect", "extract", "encrypt", "decrypt"],
        *["rewrite", "check-password", "policy validate"],
    ],
)
def test_every_command_prints_its_help(cli: CliRunner, command: str) -> None:
    result = cli(*command.split(), "--help")
    assert result.returncode == 0, result
    assert result.stdout.startswith("usage: ziplet")


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["list", "--help"], ["--long", "--json", "ARCHIVE"]),
        (
            ["test", "--help"],
            [
                "--verbose",
                "--json",
                "--password-file",
                "--password-stdin",
            ],
        ),
        (
            ["inspect", "--help"],
            ["--policy", "--policy-json", "--destination", "--json"],
        ),
        (["policy", "--help"], ["show", "validate"]),
        (["policy", "show", "--help"], ["--policy", "--policy-json"]),
        (["policy", "validate", "--help"], ["FILE", "--json"]),
    ],
)
def test_each_command_documents_its_options(
    cli: CliRunner, args: list[str], expected: list[str]
) -> None:
    result = cli(*args)
    assert result.returncode == 0, result
    for text in expected:
        assert text in result.stdout, text


def test_password_options_sit_under_options_not_in_a_group_of_their_own(
    cli: CliRunner,
) -> None:
    text = cli("test", "--help").stdout
    assert "Password options" not in text
    assert "--echo-char" not in text
    assert text.index("\nOptions:") < text.index("\n  --password-file")


def test_encryption_options_sit_under_options_without_a_group_of_their_own(
    cli: CliRunner,
) -> None:
    for command in ("create", "rewrite"):
        text = cli(command, "--help").stdout
        assert "\nEncryption:" not in text
        assert text.index("\nOptions:") < text.index("\n  --protect ")


def test_no_help_mentions_the_password_environment_variable() -> None:
    for parser in _all_parsers(build_parser()):
        assert "ZIPLET_PASSWORD" not in parser.format_help(), parser.prog


def test_version_matches_the_installed_distribution(cli: CliRunner) -> None:
    result = cli("--version")
    assert result.returncode == 0, result
    assert result.stdout == f"ziplet {version('ziplet')}\n"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ([], "Commands:"),
        (["frobnicate"], "unknown command 'frobnicate'"),
        (["list"], "ARCHIVE"),
        (["policy", "show", "extra"], "unrecognized arguments"),
        (["list", "--no-such-option", "a.zip"], "unrecognized arguments"),
        (["policy"], "COMMAND"),
        (["policy", "explode"], "unknown command 'explode'"),
        (["policy", "validate"], "FILE"),
    ],
)
def test_usage_errors_exit_2_with_usage_on_stderr(
    cli: CliRunner, args: list[str], message: str
) -> None:
    result = cli(*args)
    assert result.returncode == 2, result
    assert result.stdout == ""
    assert "usage: ziplet" in result.stderr
    assert message in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "command",
    ["list", "test", "inspect", "create", "extract", "check-password", "encrypt"]
    + ["decrypt", "rewrite", "policy", "policy validate"],
)
def test_a_command_given_no_arguments_shows_its_help(
    cli: CliRunner, command: str
) -> None:
    result = cli(*command.split())
    assert result.returncode == 2, result
    assert result.stdout == ""
    assert result.stderr.startswith(f"usage: ziplet {command}")
    assert "ziplet: error" not in result.stderr


@pytest.mark.parametrize(
    ("args", "prog"),
    [
        (["list", "a.zip", "-q"], "ziplet list"),
        (["policy", "show", "--bogus"], "ziplet policy show"),
        (["policy", "validate", "a.json", "-q"], "ziplet policy validate"),
    ],
)
def test_unrecognized_arguments_show_the_commands_own_usage_and_a_hint(
    cli: CliRunner, args: list[str], prog: str
) -> None:
    result = cli(*args)
    assert result.returncode == 2, result
    assert result.stderr.startswith(f"usage: {prog} ")
    assert f"{prog}: error: unrecognized arguments: " in result.stderr
    assert f"  Run '{prog} --help' to see all options.\n" in result.stderr


@pytest.mark.parametrize("shell", ["bash", "fish", "tcsh", "zsh"])
def test_print_completions_prints_a_script_that_knows_the_commands(
    cli: CliRunner, shell: str
) -> None:
    pytest.importorskip("shtab")
    result = cli("--print-completions", shell)
    assert result.returncode == 0, result
    assert result.stderr == ""
    for name in ("check-password", "exit-codes", "print-completions"):
        assert name in result.stdout


def test_print_completions_without_shtab_names_the_extra(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ziplet.cli import main

    monkeypatch.setitem(sys.modules, "shtab", None)  # makes ``import shtab`` fail
    assert main(["--print-completions", "fish"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ziplet[completion]" in captured.err


def test_print_completions_refuses_an_unknown_shell(cli: CliRunner) -> None:
    result = cli("--print-completions", "nushell")
    assert result.returncode == 2, result
    assert "invalid choice: 'nushell'" in result.stderr


def test_option_abbreviations_are_refused(cli: CliRunner, workdir: Path) -> None:
    """Scripts must not silently depend on a prefix that could become ambiguous."""
    archive = write_archive(workdir / "a.zip", [("a.txt", b"x")])
    result = cli("inspect", str(archive), "--pol", "{}")
    assert result.returncode == 2, result
    assert "unrecognized arguments" in result.stderr


def test_console_script_and_module_entry_point_agree(workdir: Path) -> None:
    script = Path(sys.executable).with_name("ziplet")
    if not script.exists():
        pytest.skip("console script is not installed in this environment")
    archive = write_archive(workdir / "a.zip", [("one.txt", b"1"), ("two.txt", b"2")])

    def via_script(*args: str) -> Result:
        done = subprocess.run(
            [str(script), *args], capture_output=True, env=clean_env(), timeout=60
        )
        return Result(done.returncode, done.stdout.decode(), done.stderr.decode())

    listed = via_script("list", str(archive))
    assert listed.stdout == "one.txt\ntwo.txt\n"
    assert listed.returncode == 0
    assert via_script("--version").stdout == f"ziplet {version('ziplet')}\n"
    assert via_script("list", str(workdir / "missing.zip")).returncode == 1


def test_main_returns_the_exit_code_in_process(
    workdir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from ziplet.cli import main

    archive = write_archive(workdir / "a.zip", [("a.txt", b"x")])
    assert main(["list", str(archive)]) == 0
    assert capsys.readouterr().out == "a.txt\n"
    assert main(["list", str(workdir / "missing.zip")]) == 1
    assert "cannot open" in capsys.readouterr().err
    assert main(["frobnicate"]) == 2
    assert main(["--version"]) == 0


def _all_parsers(parser: argparse.ArgumentParser) -> list[argparse.ArgumentParser]:
    found = [parser]
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            subparsers = cast(
                "argparse._SubParsersAction[argparse.ArgumentParser]", action
            )
            for sub in subparsers._name_parser_map.values():
                found.extend(_all_parsers(sub))
    return found


def test_every_argument_and_option_has_a_capitalised_description() -> None:
    for parser in _all_parsers(build_parser()):
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                continue
            assert action.help, f"{parser.prog}: {action.dest} has no help"
        text = parser.format_help()
        assert "positional arguments" not in text, parser.prog
        assert "\noptions:" not in text, parser.prog


def test_defaults_are_announced_after_a_full_stop_as_default_colon() -> None:
    for parser in _all_parsers(build_parser()):
        for action in parser._actions:
            help_text = action.help or ""
            if "default" in help_text.lower():
                assert ". Default: " in help_text, f"{parser.prog}: {action.dest}"


def test_policy_options_sit_under_options_without_a_group_of_their_own(
    cli: CliRunner,
) -> None:
    for args in (["inspect"], ["extract"], ["policy", "show"]):
        text = cli(*args, "--help").stdout
        assert "Policy:" not in text
        assert "Layered" not in text
        assert text.index("\nOptions:") < text.index("\n  --policy ")


def test_options_are_listed_alphabetically() -> None:
    for parser in _all_parsers(build_parser()):
        text = parser.format_help()
        if "\nOptions:\n" not in text:
            continue
        section = text.split("\nOptions:\n")[1].split("\n\n")[0]
        names = re.findall(r"^  (?:-\w, )?--([\w-]+)", section, re.MULTILINE)
        assert names == sorted(names, key=str.lower), parser.prog
