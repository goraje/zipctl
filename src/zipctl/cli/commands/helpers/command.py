"""How a subcommand is added to the parser."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from difflib import get_close_matches
from typing import TYPE_CHECKING, TypeVar, cast

from typing_extensions import override

from zipctl.cli.context import Context
from zipctl.cli.errors import UsageError
from zipctl.cli.formatter import HelpFormatter
from zipctl.cli.limits import add_limit_options, add_reading_options, limits_from_args

__all__ = ["CommandsAction", "Handler", "Subparsers", "add_command", "add_subcommands"]

_Args = TypeVar("_Args")

Handler = Callable[[argparse.Namespace, Context], int]

# argparse's subparsers action is generic only for type checkers
if TYPE_CHECKING:
    Subparsers = argparse._SubParsersAction[argparse.ArgumentParser]  # pyright: ignore[reportPrivateUsage]
else:
    Subparsers = argparse._SubParsersAction


def add_command(
    subparsers: Subparsers,
    name: str,
    handler: Callable[[_Args, Context], int] | None,
    help_text: str,
    description: str | None = None,
) -> argparse.ArgumentParser:
    """Add subcommand *name* running *handler* to *subparsers*.

    *handler* is ``None`` for a command that only groups further subcommands.
    Its *_Args* is the shape of the options the command adds: the namespace
    argparse builds is cast to it, the one place that trusts the parser.
    """
    parser: argparse.ArgumentParser = subparsers.add_parser(
        name,
        help=help_text,
        description=description or help_text,
        allow_abbrev=False,
        formatter_class=HelpFormatter,
    )
    if handler is not None:
        add_limit_options(parser)
        add_reading_options(parser)
        parser.set_defaults(json=False, quiet=False, verbose=False)  # the output mode

        def run(args: argparse.Namespace, ctx: Context) -> int:
            ctx.output.json = cast(bool, args.json)
            ctx.output.quiet = cast(bool, args.quiet)
            ctx.output.verbose = cast(bool, args.verbose)
            ctx.allow_prepended_data = cast(bool, args.allow_prepended_data)
            try:
                ctx.limits = limits_from_args(args)
            except ValueError as exc:
                raise UsageError(str(exc)) from None
            return handler(cast("_Args", args), ctx)

        parser.set_defaults(handler=run)
    return parser


class CommandsAction(Subparsers):
    """The command choice, suggesting the nearest command for a mistyped one."""

    def __init__(
        self,
        option_strings: Sequence[str],
        prog: str,
        parser_class: type[argparse.ArgumentParser],
        dest: str = argparse.SUPPRESS,
        required: bool = False,
        help: str | None = None,  # noqa: A002  # mirrors argparse.Action
        metavar: str | tuple[str, ...] | None = None,
    ) -> None:
        super().__init__(
            option_strings, prog, parser_class, dest, required, help, metavar
        )
        # argparse would reject an unknown name before __call__ gets to suggest one
        self.choices = None  # type: ignore[assignment]  # ty: ignore[invalid-assignment]  # pyright: ignore[reportAttributeAccessIssue, reportUnannotatedClassAttribute]

    @override
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[str] | None,
        option_string: str | None = None,
    ) -> None:
        assert values is not None
        assert not isinstance(values, str)
        name = str(values[0])
        if name not in self._name_parser_map:
            lines = [f"unknown command {name!r}"]
            for close in get_close_matches(name, self._name_parser_map, n=1):
                lines.append(f"  Did you mean {close!r}?")
            lines.append(f"  Run '{parser.prog} --help' to see all commands.")
            parser.error("\n".join(lines))
        super().__call__(parser, namespace, values, option_string)
        # argparse reports these at the top; the command's own usage is more useful
        extras: list[str] | None = getattr(
            namespace,
            argparse._UNRECOGNIZED_ARGS_ATTR,  # pyright: ignore[reportPrivateUsage]
            None,
        )
        if extras:
            sub = self._name_parser_map[name]
            sub.error(
                f"unrecognized arguments: {' '.join(_redacted(extras))}\n"
                f"  Run '{sub.prog} --help' to see all options."
            )


def _redacted(extras: list[str]) -> list[str]:
    """*extras* with what looks like a mistyped password option's value hidden."""
    shown: list[str] = []
    hide_next = False
    for extra in extras:
        option, equals, _ = extra.partition("=")
        secret = option.startswith("--") and "pass" in option.lower()
        if hide_next and not extra.startswith("-"):
            shown.append("***")
        elif secret and equals:
            shown.append(f"{option}=***")
        else:
            shown.append(extra)
        hide_next = secret and not equals
    return shown


def add_subcommands(parser: argparse.ArgumentParser, dest: str) -> Subparsers:
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
