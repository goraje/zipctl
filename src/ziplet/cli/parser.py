"""The argparse command tree."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Any, NoReturn

from ziplet.cli.commands import (
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
from ziplet.cli.commands import list as list_command
from ziplet.cli.commands.helpers.command import CommandsAction, add_subcommands
from ziplet.cli.errors import EXIT_FAILURE, EXIT_USAGE, exit_codes_table
from ziplet.cli.formatter import HelpFormatter

__all__ = ["build_parser"]

_COMMANDS = (
    list_command,
    test,
    inspect,
    create,
    extract,
    check_password,
    encrypt,
    decrypt,
    rewrite,
    policy,
)


class _Parser(argparse.ArgumentParser):
    """Show the help, not an error, when a command that needs arguments gets none."""

    _bare = False

    def parse_known_args(self, args: Any = None, namespace: Any = None) -> Any:
        self._bare = args is not None and not args
        return super().parse_known_args(args, namespace)

    def error(self, message: str) -> NoReturn:
        if self._bare:
            self.print_help(sys.stderr)
            self.exit(EXIT_USAGE)
        super().error(message)


class _VersionAction(argparse.Action):
    """``--version``, looking the version up only when it is asked for."""

    def __init__(self, option_strings: Sequence[str], dest: str, **kwargs: Any):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        from importlib.metadata import PackageNotFoundError, version

        try:
            text = version("ziplet")
        except PackageNotFoundError:
            text = "unknown"
        print(f"ziplet {text}")
        parser.exit()


class _ExitCodesAction(argparse.Action):
    """``--exit-codes``: print the table of exit codes and stop."""

    def __init__(self, option_strings: Sequence[str], dest: str, **kwargs: Any):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
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

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        try:
            import shtab
        except ImportError:
            parser.exit(
                EXIT_FAILURE,
                "ziplet: error: shell completion needs the 'completion' extra "
                "(pip install 'ziplet[completion]')\n",
            )
        _expose_commands(parser)
        print(shtab.complete(parser, values))
        parser.exit()


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="ziplet",
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

    for module in _COMMANDS:  # the order ``--help`` shows them in
        module.register(subparsers)
    return parser
