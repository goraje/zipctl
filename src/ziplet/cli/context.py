"""The streams and environment a command runs against."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import BinaryIO, TextIO

from ziplet.cli.errors import UsageError

__all__ = ["Context"]


@dataclass
class Context:
    """The streams and environment a command runs against."""

    stdin: TextIO
    stdout: TextIO
    stderr: TextIO
    environ: Mapping[str, str]
    _stdin_user: str | None = field(default=None, init=False, repr=False)
    warned: bool = field(default=False, init=False, repr=False)

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

    def out(self, line: str = "") -> None:
        print(line, file=self.stdout)

    def err(self, line: str = "") -> None:
        print(line, file=self.stderr)

    def warn(self, text: str) -> None:
        self.warned = True
        self.err(f"ziplet: warning: {text}")
