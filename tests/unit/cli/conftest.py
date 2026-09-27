"""Shared builders for the CLI unit tests."""

from __future__ import annotations

import io
from collections.abc import Mapping

from zipctl.cli.context import Context


def new_context(environ: Mapping[str, str] | None = None, stdin: str = "") -> Context:
    return Context(io.StringIO(stdin), io.StringIO(), io.StringIO(), environ or {})
