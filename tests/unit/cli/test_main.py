"""``main()``: how failures are reported (debug traceback, JSON error)."""

from __future__ import annotations

import argparse
import errno
import json
import os
import signal
import threading
from collections.abc import Callable

import pytest

from zipctl.cli import main
from zipctl.cli.context import Context
from zipctl.cli.errors import CliError


def _raising(error: BaseException) -> Callable[[argparse.Namespace, Context], int]:
    def handler(_args: argparse.Namespace, _ctx: Context) -> int:
        raise error

    return handler


def _install(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    monkeypatch.setattr("zipctl.cli.commands.list.cmd_list", _raising(error))


def test_an_unexpected_error_is_named_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("ZIPCTL_DEBUG", raising=False)
    _install(monkeypatch, TypeError("boom"))
    assert main(["list", "a.zip"]) == 1
    err = capsys.readouterr().err
    assert "zipctl: error: unexpected TypeError: boom" in err
    assert "ZIPCTL_DEBUG=1" in err
    assert "Traceback" not in err


def test_debug_adds_the_traceback_and_the_hidden_cause(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ZIPCTL_DEBUG", "1")
    try:
        try:
            raise OSError(13, "Permission denied", "x")
        except OSError:
            raise CliError("cannot read x") from None
    except CliError as hidden:
        _install(monkeypatch, hidden)
    assert main(["list", "a.zip"]) == 1
    err = capsys.readouterr().err
    assert "zipctl: error: cannot read x" in err
    assert "Traceback" in err
    assert "PermissionError" in err


def test_json_failure_is_also_reported_on_standard_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, CliError("bad thing", 2, ("first", "second")))
    assert main(["list", "a.zip", "--json"]) == 2
    captured = capsys.readouterr()
    assert "zipctl: error: bad thing" in captured.err
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


def test_unrelated_invalid_argument_is_not_a_broken_pipe(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, OSError(errno.EINVAL, "Invalid argument", "archive.zip"))
    assert main(["list", "archive.zip"]) == 1
    assert "archive.zip" in capsys.readouterr().err


def test_json_interrupt_is_also_reported_on_standard_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, KeyboardInterrupt())
    assert main(["list", "a.zip", "--json"]) == 130
    captured = capsys.readouterr()
    assert "zipctl: interrupted" in captured.err
    assert json.loads(captured.out)["code"] == 130


@pytest.mark.skipif(
    not hasattr(signal, "SIGTERM") or os.name != "posix", reason="POSIX signals"
)
@pytest.mark.skipif(
    threading.current_thread() is not threading.main_thread(),
    reason="signal handlers need the main thread",
)
def test_sigterm_unwinds_as_system_exit_and_restores_the_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(_args: argparse.Namespace, _ctx: Context) -> int:
        os.kill(os.getpid(), signal.SIGTERM)
        return 0

    before = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr("zipctl.cli.commands.list.cmd_list", handler)
    with pytest.raises(SystemExit) as raised:
        main(["list", "a.zip"])
    assert raised.value.code == 128 + signal.SIGTERM
    assert signal.getsignal(signal.SIGTERM) is before
