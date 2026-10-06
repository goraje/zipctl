"""The streams and environment a command runs against."""

from __future__ import annotations

import getpass
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import InitVar, dataclass, field
from typing import BinaryIO, TextIO

from zipctl.cli.errors import UsageError
from zipctl.cli.output import Output
from zipctl.limits import ArchiveLimits

__all__ = ["Context", "ask_terminal"]


def ask_terminal(label: str) -> str:
    """Prompt on the terminal, masking input where the Python version can.

    End of input answers with the empty string, like an empty answer.
    """
    try:
        if sys.version_info >= (3, 14):
            return getpass.getpass(label, echo_char="*")  # pyright: ignore[reportUnreachable]  # branch depends on the Python version
        return getpass.getpass(label)
    except EOFError:
        return ""


@dataclass
class Context:
    """The streams and environment a command runs against."""

    stdin: TextIO
    stdout: InitVar[TextIO]
    stderr: InitVar[TextIO]
    environ: Mapping[str, str]
    limits: ArchiveLimits = field(default_factory=ArchiveLimits)
    allow_prepended_data: bool = False
    prompt: InitVar[Callable[[str], str]] = ask_terminal  # asks for a secret, unechoed
    output: Output = field(init=False)
    _prompt: Callable[[str], str] = field(init=False, repr=False)
    _stdin_user: str | None = field(default=None, init=False, repr=False)

    def __post_init__(
        self, stdout: TextIO, stderr: TextIO, prompt: Callable[[str], str]
    ) -> None:
        self.output = Output(stdout, stderr)
        self._prompt = prompt  # reached only through ask, which clears the line

    @classmethod
    def from_process(cls) -> Context:
        """Bind to the current ``sys`` streams (looked up at call time)."""
        return cls(sys.stdin, sys.stdout, sys.stderr, os.environ)

    def claim_stdin(self, purpose: str) -> None:
        """Reserve standard input for *purpose*; it can only be read once."""
        if self._stdin_user is not None:
            raise UsageError(
                f"standard input cannot be used for both {self._stdin_user} "
                f"and {purpose}",
            )
        self._stdin_user = purpose

    def read_stdin(self, *, line: bool = False) -> bytes:
        """The rest of standard input, or only its next line, as bytes."""
        binary: BinaryIO | None = getattr(self.stdin, "buffer", None)
        if binary is not None:
            return binary.readline() if line else binary.read()
        text = self.stdin.readline() if line else self.stdin.read()
        return text.encode("utf-8")

    def ask(self, label: str) -> str:
        """Prompt for a secret, clearing the progress line first."""
        self.output.clear_line()
        return self._prompt(label)
