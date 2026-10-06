"""Shared builders for the CLI unit tests."""

from __future__ import annotations

import io
from collections.abc import Callable, Mapping

from zipctl.cli.context import Context, ask_terminal


def new_context(
    environ: Mapping[str, str] | None = None,
    stdin: str = "",
    prompt: Callable[[str], str] = ask_terminal,
) -> Context:
    streams = (io.StringIO(stdin), io.StringIO(), io.StringIO())
    return Context(*streams, environ or {}, prompt=prompt)
