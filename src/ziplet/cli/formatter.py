"""The help formatter every ``ziplet`` parser uses."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from typing import Any

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

    _options_section = False

    def __init__(self, prog: str, **kwargs: Any) -> None:
        kwargs.setdefault("max_help_position", 30)  # room for "-d, --destination DIR"
        super().__init__(prog, **kwargs)

    def start_section(self, heading: str | None) -> None:
        self._options_section = heading == "options"
        if heading == "positional arguments":
            heading = "arguments"
        super().start_section(_capitalize(heading) if heading else heading)

    def add_arguments(self, actions: Iterable[argparse.Action]) -> None:
        if self._options_section:
            actions = sorted(actions, key=lambda action: _option_name(action).lower())
        super().add_arguments(actions)

    def _format_action(self, action: argparse.Action) -> str:
        """List subcommands directly, without argparse's ``COMMAND`` header line."""
        if isinstance(action, argparse._SubParsersAction):
            return "".join(
                super(HelpFormatter, self)._format_action(sub)
                for sub in action._get_subactions()
            )
        return super()._format_action(action)

    def _format_text(self, text: str) -> str:
        return super()._format_text(_capitalize(text))

    def _expand_help(self, action: argparse.Action) -> str:
        return _capitalize(super()._expand_help(action))
