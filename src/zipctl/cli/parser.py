"""The argparse command tree."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence
from typing import NoReturn, TypeVar, overload

from typing_extensions import override

from zipctl.cli.commands import (
    check_password,
    create,
    decrypt,
    encrypt,
    extract,
    inspect,
    policy,
    rewrite,
    test,
)
from zipctl.cli.commands import list as list_command
from zipctl.cli.commands.helpers.command import CommandsAction, add_subcommands
from zipctl.cli.errors import EXIT_FAILURE, EXIT_USAGE, exit_codes_table
from zipctl.cli.formatter import HelpFormatter

__all__ = ["build_parser"]

_N = TypeVar("_N")

# the order ``--help`` shows the commands in
_REGISTER = (
    list_command.register,
    test.register,
    inspect.register,
    create.register,
    extract.register,
    check_password.register,
    encrypt.register,
    decrypt.register,
    rewrite.register,
    policy.register,
)


class _Parser(argparse.ArgumentParser):
    """Show the help, not an error, when a command that needs arguments gets none."""

    _bare: bool = False

    @overload
    def parse_known_args(
        self, args: Iterable[str] | None = None, namespace: None = None
    ) -> tuple[argparse.Namespace, list[str]]: ...

    @overload
    def parse_known_args(
        self, args: Iterable[str] | None, namespace: _N
    ) -> tuple[_N, list[str]]: ...

    @overload
    def parse_known_args(self, *, namespace: _N) -> tuple[_N, list[str]]: ...

    @override
    def parse_known_args(
        self,
        args: Iterable[str] | None = None,
        namespace: _N | None = None,
    ) -> tuple[_N | argparse.Namespace, list[str]]:
        self._bare = isinstance(args, Sequence) and not args
        if namespace is None:
            return super().parse_known_args(args)
        return super().parse_known_args(args, namespace)

    @override
    def error(self, message: str) -> NoReturn:
        if self._bare:
            self.print_help(sys.stderr)
            self.exit(EXIT_USAGE)
        super().error(message)


class _VersionAction(argparse.Action):
    """``--version``, looking the version up only when it is asked for."""

    def __init__(
        self,
        option_strings: Sequence[str],
        dest: str,
        help: str | None = None,  # noqa: A002  # mirrors argparse.Action
    ) -> None:
        super().__init__(option_strings, dest, nargs=0, help=help)

    @override
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[str] | None,
        option_string: str | None = None,
    ) -> None:
        from importlib.metadata import PackageNotFoundError, version

        try:
            text = version("zipctl")
        except PackageNotFoundError:
            text = "unknown"
        print(f"zipctl {text}")
        parser.exit()


class _ExitCodesAction(argparse.Action):
    """``--exit-codes``: print the table of exit codes and stop."""

    def __init__(
        self,
        option_strings: Sequence[str],
        dest: str,
        help: str | None = None,  # noqa: A002  # mirrors argparse.Action
    ) -> None:
        super().__init__(option_strings, dest, nargs=0, help=help)

    @override
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[str] | None,
        option_string: str | None = None,
    ) -> None:
        print(exit_codes_table())
        parser.exit()


def _expose_commands(parser: argparse.ArgumentParser) -> None:
    """Give shtab the command names that ``CommandsAction`` hides from argparse.

    The parser is not used for parsing again, so this is safe to leave in place.
    """
    for action in parser._actions:
        if isinstance(action, CommandsAction):
            action.choices = action._name_parser_map
            for sub in action._name_parser_map.values():
                _expose_commands(sub)


class _PrintCompletionsAction(argparse.Action):
    """``--print-completions SHELL``: print the completion script and stop."""

    @override
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[str] | None,
        option_string: str | None = None,
    ) -> None:
        try:
            import shtab
        except ImportError:
            parser.exit(
                EXIT_FAILURE,
                "zipctl: error: shell completion needs the 'completion' extra "
                "(pip install 'zipctl[completion]')\n",
            )
        assert isinstance(values, str)
        _expose_commands(parser)
        print(shtab.complete(parser, values))
        parser.exit()


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="zipctl",
        description="Manage ZIP archives safely, including encrypted ones.",
        allow_abbrev=False,
        formatter_class=HelpFormatter,
    )
    parser.add_argument("--version", action=_VersionAction, help="show the version")
    parser.add_argument(
        "--exit-codes",
        action=_ExitCodesAction,
        help="show the exit codes and their meaning",
    )
    parser.add_argument(
        "--print-completions",
        action=_PrintCompletionsAction,
        choices=("bash", "fish", "tcsh", "zsh"),
        metavar="SHELL",
        help="show the completion script for SHELL. Needs the 'completion' extra",
    )
    subparsers = add_subcommands(parser, "command")

    for register in _REGISTER:
        register(subparsers)
    return parser
