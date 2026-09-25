"""Interactive password prompts, driven through a real pseudo-terminal."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import ziplet
from tests.functional.cli.support import (
    HAS_PTY,
    PASSWORD,
    special_info,
    write_archive,
)
from tests.functional.cli.support import run_in_terminal as terminal
from ziplet import ZipFile

pytestmark = pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")

PW = PASSWORD.encode()
BODY = b"prompted payload " * 100
# getpass can only mask input from Python 3.14 on.
CAN_MASK = sys.version_info >= (3, 14)


def _archive(workdir: Path, members: list[tuple[str, bytes]]) -> Path:
    """An AES archive where each member has its own password."""
    path = workdir / "per.zip"
    with ZipFile(path, "w", encryption=ziplet.WZ_AES) as zf:
        for name, password in members:
            zf.writestr(name, BODY, password=password)
    return path


@pytest.fixture
def shared(workdir: Path) -> Path:
    return write_archive(
        workdir / "shared.zip",
        [("a.txt", BODY), ("b.txt", BODY), ("c.txt", BODY)],
        encryption=ziplet.WZ_AES,
        password=PW,
    )


def test_a_shared_password_is_asked_for_once(shared: Path) -> None:
    result, prompts = terminal("test", str(shared), replies=[PASSWORD])
    assert result.returncode == 0, result
    assert result.stdout == "Tested 3 members: all OK\n"
    assert prompts == 1
    assert "Password for a.txt: " in result.stderr


def test_the_typed_password_is_never_echoed_back(shared: Path) -> None:
    result, _ = terminal("test", str(shared), replies=[PASSWORD])
    assert result.returncode == 0, result
    assert PASSWORD not in result.stderr + result.stdout


def test_typed_input_is_masked_with_stars_where_python_allows(shared: Path) -> None:
    result, _ = terminal("test", str(shared), replies=[PASSWORD])
    assert result.returncode == 0, result
    assert ("*" * len(PASSWORD) in result.stderr) == CAN_MASK


def test_explicit_password_prompt_flag(shared: Path) -> None:
    result, prompts = terminal(
        "test", "--password-prompt", str(shared), replies=[PASSWORD]
    )
    assert result.returncode == 0, result
    assert prompts == 1


def test_a_wrong_password_can_be_retried(shared: Path) -> None:
    result, prompts = terminal("test", str(shared), replies=["nope", PASSWORD])
    assert result.returncode == 0, result
    assert prompts == 2
    assert result.stderr.count("incorrect password, try again") == 1


def test_three_wrong_passwords_fail_only_that_member(shared: Path) -> None:
    """Every member gets its own three tries: another one may use another password."""
    result, prompts = terminal("test", str(shared), replies=["one", "two", "three"] * 3)
    assert result.returncode == 1, result
    assert prompts == 9
    assert result.stderr.count("incorrect password, try again") == 6
    assert result.stdout.count("wrong password") == 3
    assert result.stdout.splitlines()[-1] == "Tested 3 members: 3 failed"


def test_an_empty_answer_stops_all_further_prompting(shared: Path) -> None:
    result, prompts = terminal("test", str(shared), replies=[""])
    assert result.returncode == 1, result
    assert prompts == 1
    assert result.stdout.count("password required") == 3
    assert result.stdout.splitlines()[-1] == "Tested 3 members: 3 failed"


@pytest.mark.skipif(
    sys.version_info >= (3, 14), reason="Ctrl-D does not end masked input"
)
def test_end_of_input_stops_all_further_prompting(shared: Path) -> None:
    from tests.functional.cli.support import END_OF_INPUT

    result, prompts = terminal("test", str(shared), replies=[END_OF_INPUT])
    assert result.returncode == 1, result
    assert prompts == 1
    assert result.stdout.count("password required") == 3
    assert "Traceback" not in result.stderr


def test_giving_up_still_uses_passwords_already_known(workdir: Path) -> None:
    """Stop asking, but keep using the passwords collected so far."""
    path = _archive(
        workdir,
        [("a.txt", b"pass-one"), ("b.txt", b"pass-two"), ("c.txt", b"pass-one")],
    )
    result, prompts = terminal("test", "-v", str(path), replies=["pass-one", ""])
    assert prompts == 2
    assert "OK      a.txt" in result.stdout
    assert "FAILED  b.txt: wrong password" in result.stdout
    assert "OK      c.txt" in result.stdout


def test_different_passwords_are_asked_once_each_and_then_remembered(
    workdir: Path,
) -> None:
    path = _archive(
        workdir,
        [("a.txt", b"pass-one"), ("b.txt", b"pass-two"), ("c.txt", b"pass-one"),
         ("d.txt", b"pass-two")],
    )  # fmt: skip
    result, prompts = terminal("test", str(path), replies=["pass-one", "pass-two"])
    assert result.returncode == 0, result
    assert prompts == 2
    assert "Password for a.txt: " in result.stderr
    assert "Password for b.txt: " in result.stderr
    assert "Password for c.txt: " not in result.stderr


def test_static_sources_and_prompts_work_together(workdir: Path) -> None:
    path = _archive(workdir, [("a.txt", b"pass-one"), ("b.txt", b"pass-two")])
    result, prompts = terminal(
        "test", str(path), replies=["pass-two"], env={"ZIPLET_PASSWORD": "pass-one"}
    )
    assert result.returncode == 0, result
    assert prompts == 1
    assert "Password for b.txt: " in result.stderr


def test_a_password_file_is_tried_before_prompting(workdir: Path) -> None:
    path = _archive(workdir, [("a.txt", b"pass-one"), ("b.txt", b"pass-two")])
    passfile = workdir / "pw"
    passfile.write_bytes(b"pass-one\n")
    result, prompts = terminal(
        "test", "--password-file", str(passfile), str(path), replies=["pass-two"]
    )
    assert result.returncode == 0, result
    assert prompts == 1


def test_password_stdin_refuses_a_terminal(workdir: Path) -> None:
    """Typing a password on a terminal would echo it, and used to hang."""
    path = _archive(workdir, [("a.txt", b"pass-one")])
    result, prompts = terminal("test", "--password-stdin", str(path), replies=[])
    assert result.returncode == 2, result
    assert prompts == 0
    assert "not typed at a terminal" in result.stderr
    assert "--password-prompt" in result.stderr


def test_zipcrypto_prompts_work_too(workdir: Path) -> None:
    path = write_archive(
        workdir / "zc.zip",
        [("a.txt", BODY), ("b.txt", BODY)],
        encryption=ziplet.ZIP_CRYPTO,
        password=PW,
    )
    result, prompts = terminal("test", str(path), replies=[PASSWORD])
    assert result.returncode == 0, result
    assert prompts == 1


def test_prompts_name_members_safely(workdir: Path) -> None:
    name = "evil\x1b[31mred\nname.txt"
    path = _archive(workdir, [(name, PW)])
    result, prompts = terminal("test", str(path), replies=[PASSWORD])
    assert result.returncode == 0, result
    assert prompts == 1
    assert "\x1b" not in result.stderr
    assert "Password for evil\\x1b[31mred\\x0aname.txt: " in result.stderr


def test_unencrypted_members_never_prompt(workdir: Path) -> None:
    path = write_archive(workdir / "plain.zip", [("a.txt", BODY)])
    result, prompts = terminal("test", str(path), replies=[])
    assert result.returncode == 0
    assert prompts == 0


def test_interrupting_a_prompt_exits_130_without_a_traceback(shared: Path) -> None:
    result, prompts = terminal("test", str(shared), interrupt_at_prompt=1)
    assert result.returncode == 130, result
    assert prompts == 1
    assert "ziplet: interrupted" in result.stderr
    assert "Traceback" not in result.stderr


def test_terminal_use_does_not_change_json_output_on_stdout(shared: Path) -> None:
    import json

    result, _ = terminal("test", "--json", str(shared), replies=[PASSWORD])
    assert result.returncode == 0, result
    assert json.loads(result.stdout)["ok"] is True
    assert "Password for" in result.stderr


def test_special_names_do_not_break_the_prompt_flow(workdir: Path) -> None:
    path = workdir / "s.zip"
    with ZipFile(path, "w", encryption=ziplet.WZ_AES) as zf:
        zf.setpassword(PW)
        zf.writestr(special_info("dir/", 0o40755), b"", encryption=None)
        zf.writestr("dir/secret.txt", BODY)
    result, prompts = terminal("test", str(path), replies=[PASSWORD])
    assert result.returncode == 0, result
    assert prompts == 1


def test_password_prompt_ignores_the_environment_variable(shared: Path) -> None:
    from_env = terminal("test", str(shared), env={"ZIPLET_PASSWORD": PASSWORD})
    assert from_env[1] == 0
    result, prompts = terminal(
        "test",
        "--password-prompt",
        str(shared),
        env={"ZIPLET_PASSWORD": PASSWORD},
        replies=[PASSWORD],
    )
    assert result.returncode == 0, result
    assert prompts == 1


def test_password_prompt_asks_for_a_new_password_despite_the_environment(
    workdir: Path,
) -> None:
    source = write_archive(workdir / "plain.zip", [("a.txt", BODY)])
    out = workdir / "out.zip"
    result, prompts = terminal(
        "encrypt",
        "--password-prompt",
        str(source),
        str(out),
        env={"ZIPLET_PASSWORD": "from the environment"},
        replies=[PASSWORD, PASSWORD],
    )
    assert result.returncode == 0, result
    assert prompts == 2  # the password, then its confirmation
    with ZipFile(out) as zf:
        assert zf.read("a.txt", pwd=PW) == BODY


def test_password_prompt_makes_check_password_ask_despite_the_environment(
    shared: Path,
) -> None:
    result, prompts = terminal(
        "check-password",
        "--password-prompt",
        str(shared),
        env={"ZIPLET_PASSWORD": "from the environment"},
        replies=[PASSWORD],
    )
    assert result.returncode == 0, result
    assert prompts == 1
