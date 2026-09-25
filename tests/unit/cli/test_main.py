"""``main()``: how failures are reported (debug traceback, JSON error)."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable

import pytest

from ziplet.cli import main
from ziplet.cli.context import Context
from ziplet.cli.errors import CliError


def _raising(error: BaseException) -> Callable[[argparse.Namespace, Context], int]:
    def handler(args: argparse.Namespace, ctx: Context) -> int:
        raise error

    return handler


def _install(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    monkeypatch.setattr("ziplet.cli.commands.list.cmd_list", _raising(error))


def test_an_unexpected_error_is_named_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("ZIPLET_DEBUG", raising=False)
    _install(monkeypatch, TypeError("boom"))
    assert main(["list", "a.zip"]) == 1
    err = capsys.readouterr().err
    assert "ziplet: error: unexpected TypeError: boom" in err
    assert "ZIPLET_DEBUG=1" in err
    assert "Traceback" not in err


def test_debug_adds_the_traceback_and_the_hidden_cause(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ZIPLET_DEBUG", "1")
    try:
        try:
            raise OSError(13, "Permission denied", "x")
        except OSError:
            raise CliError("cannot read x") from None
    except CliError as hidden:
        _install(monkeypatch, hidden)
    assert main(["list", "a.zip"]) == 1
    err = capsys.readouterr().err
    assert "ziplet: error: cannot read x" in err
    assert "Traceback" in err
    assert "PermissionError" in err


def test_json_failure_is_also_reported_on_standard_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, CliError("bad thing", 2, ("first", "second")))
    assert main(["list", "a.zip", "--json"]) == 2
    captured = capsys.readouterr()
    assert "ziplet: error: bad thing" in captured.err
    assert json.loads(captured.out) == {
        "ok": False,
        "error": "bad thing",
        "code": 2,
        "details": ["first", "second"],
    }


def test_without_json_standard_output_stays_empty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, CliError("bad thing"))
    assert main(["list", "a.zip"]) == 1
    assert capsys.readouterr().out == ""
