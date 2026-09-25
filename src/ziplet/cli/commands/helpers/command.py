"""How a subcommand is added to the parser."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from difflib import get_close_matches
from typing import Any

from ziplet.cli.context import Context
from ziplet.cli.formatter import HelpFormatter

__all__ = ["CommandsAction", "Handler", "add_command", "add_subcommands"]

Handler = Callable[[argparse.Namespace, Context], int]


def add_command(
    subparsers: Any,
    name: str,
    handler: Handler | None,
    help_text: str,
    description: str | None = None,
) -> argparse.ArgumentParser:
    """Add subcommand *name* running *handler* to *subparsers*.

    *handler* is ``None`` for a command that only groups further subcommands.
    """
    parser: argparse.ArgumentParser = subparsers.add_parser(
        name,
        help=help_text,
        description=description or help_text,
        allow_abbrev=False,
        formatter_class=HelpFormatter,
    )
    if handler is not None:
        parser.set_defaults(handler=handler)
    return parser


class CommandsAction(argparse._SubParsersAction):  # type: ignore[type-arg]
    """The command choice, suggesting the nearest command for a mistyped one."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # argparse would reject an unknown name before __call__ gets to suggest one
        self.choices = None  # type: ignore[assignment]  # ty: ignore[invalid-assignment]

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        name = values[0]
        if name not in self._name_parser_map:
            lines = [f"unknown command {name!r}"]
            for close in get_close_matches(name, self._name_parser_map, n=1):
                lines.append(f"  Did you mean {close!r}?")
            lines.append(f"  Run '{parser.prog} --help' to see all commands.")
            parser.error("\n".join(lines))
        super().__call__(parser, namespace, values, option_string)
        # argparse reports these at the top; the command's own usage is more useful
        extras = getattr(namespace, argparse._UNRECOGNIZED_ARGS_ATTR, None)
        if extras:
            sub = self._name_parser_map[name]
            sub.error(
                f"unrecognized arguments: {' '.join(extras)}\n"
                f"  Run '{sub.prog} --help' to see all options."
            )


def add_subcommands(parser: argparse.ArgumentParser, dest: str) -> Any:
    """Give *parser* a ``Commands`` section listing the subcommands added to it."""
    subparsers = parser.add_subparsers(
        action=CommandsAction,
        title="Commands",
        dest=dest,
        metavar="COMMAND",
        required=True,
    )
    groups = parser._action_groups
    groups.insert(1, groups.pop())  # "Commands" before "Options"
    return subparsers
