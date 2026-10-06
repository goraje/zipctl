"""The help formatter every ``zipctl`` parser uses."""

from __future__ import annotations

import argparse
from collections.abc import Iterable

from typing_extensions import override

__all__ = ["HelpFormatter"]


def _capitalize(text: str) -> str:
    """Upper-case the first letter only (``str.capitalize`` would lower the rest)."""
    return text[:1].upper() + text[1:]


def _option_name(action: argparse.Action) -> str:
    """The name options are sorted by: the long option, without its dashes."""
    strings = action.option_strings
    return next((s for s in strings if s.startswith("--")), strings[0]).lstrip("-")


class HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Capitalise headings and descriptions; list the options alphabetically."""

    _options_section: bool = False

    def __init__(self, prog: str) -> None:
        # a wider help column leaves room for "-d, --destination DIR"
        super().__init__(prog, max_help_position=30)

    @override
    def start_section(self, heading: str | None) -> None:
        self._options_section = heading == "options"
        if heading == "positional arguments":
            heading = "arguments"
        super().start_section(_capitalize(heading) if heading else heading)

    @override
    def add_arguments(self, actions: Iterable[argparse.Action]) -> None:
        if self._options_section:
            actions = sorted(actions, key=lambda action: _option_name(action).lower())
        super().add_arguments(actions)

    @override
    def _format_action(self, action: argparse.Action) -> str:
        """List subcommands directly, without argparse's ``COMMAND`` header line."""
        if isinstance(action, argparse._SubParsersAction):  # pyright: ignore[reportPrivateUsage]
            return "".join(
                super(HelpFormatter, self)._format_action(sub)
                for sub in action._get_subactions()
            )
        return super()._format_action(action)

    @override
    def _format_text(self, text: str) -> str:
        return super()._format_text(_capitalize(text))

    @override
    def _expand_help(self, action: argparse.Action) -> str:
        return _capitalize(super()._expand_help(action))
