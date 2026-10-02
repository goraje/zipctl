"""Matching known and typed passwords to members, without a real archive."""

from __future__ import annotations

import io
from types import SimpleNamespace
from typing import cast

from tests.unit.cli.conftest import new_context
from zipctl import ZIP_CRYPTO
from zipctl.cli.commands.helpers.passwords.pool import PasswordPool, PasswordProblem
from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.password import (
    MemberPasswordCheck,
    PasswordCheckResult,
    PasswordStatus,
)


class FakeZip:
    """Accepts the password each member was set up with."""

    def __init__(
        self, secrets: dict[str, bytes], corrupt: frozenset[str] | None = None
    ) -> None:
        self.secrets: dict[str, bytes] = secrets
        self.corrupt: frozenset[str] = corrupt or frozenset()
        self.checked: list[bytes] = []

    def check_password(
        self, password: bytes, members: list[ZipInfo], *, full: bool = False
    ) -> PasswordCheckResult:
        name = members[0].filename
        assert full
        self.checked.append(password)
        if name in self.corrupt:
            status = PasswordStatus.CORRUPT
        elif self.secrets[name] == password:
            status = PasswordStatus.ACCEPTED
        else:
            status = PasswordStatus.REJECTED
        return PasswordCheckResult((MemberPasswordCheck(name, status),))


class Typing:
    """A prompt that answers with *answers* in turn (``None`` is end of input).

    End of input answers with the empty string, like the real prompt.
    """

    def __init__(self, *answers: str | None) -> None:
        self._answers: list[str | None] = list(answers)
        self.asked: list[str] = []

    def __call__(self, label: str) -> str:
        self.asked.append(label)
        answer = self._answers.pop(0)
        return "" if answer is None else answer


def resolve(pool: PasswordPool, zf: FakeZip, name: str) -> bytes | PasswordProblem:
    info = cast("ZipInfo", SimpleNamespace(filename=name))  # pyright: ignore[reportInvalidCast]  # duck-typed stand-in
    return pool.resolve(cast("ZipFile", zf), info)  # pyright: ignore[reportInvalidCast]  # duck-typed stand-in


def pool(*known: bytes, prompt: Typing | None = None) -> PasswordPool:
    """A pool that may prompt only when given a *prompt*."""
    return PasswordPool(
        list(known),
        new_context(),
        can_prompt=prompt is not None,
        prompt=prompt or Typing(),
    )


def test_a_known_password_is_found_without_asking() -> None:
    zf = FakeZip({"a": b"one", "b": b"two"})
    assert resolve(pool(b"one", b"two"), zf, "b") == b"two"


def test_no_passwords_and_no_terminal_means_missing() -> None:
    assert resolve(pool(), FakeZip({"a": b"x"}), "a") is PasswordProblem.MISSING


def test_only_wrong_passwords_and_no_terminal_means_wrong() -> None:
    assert resolve(pool(b"nope"), FakeZip({"a": b"x"}), "a") is PasswordProblem.WRONG


def test_a_damaged_member_is_reported_as_corrupt_not_wrong() -> None:
    zf = FakeZip({"a": b"x"}, corrupt=frozenset({"a"}))
    assert resolve(pool(b"x"), zf, "a") is PasswordProblem.CORRUPT


def test_an_accepted_typed_password_is_remembered_for_the_next_member() -> None:
    zf = FakeZip({"a": b"secret", "b": b"secret"})
    prompt = Typing("secret")
    shared = pool(prompt=prompt)
    assert resolve(shared, zf, "a") == b"secret"
    assert resolve(shared, zf, "b") == b"secret"
    assert prompt.asked == ["Password for a: "]


def test_the_latest_accepted_password_is_tried_first() -> None:
    zf = FakeZip({"a": b"one", "b": b"two", "c": b"two"})
    shared = pool(prompt=Typing("one", "two"))
    resolve(shared, zf, "a")
    resolve(shared, zf, "b")
    zf.checked.clear()
    assert resolve(shared, zf, "c") == b"two"
    assert zf.checked == [b"two"]


def test_every_member_gets_its_own_three_wrong_answers() -> None:
    """Giving up on one member does not stop the prompts for the next."""
    prompt = Typing("x", "y", "z", "x", "y", "z")
    zf = FakeZip({"a": b"secret", "b": b"secret"})
    shared = pool(prompt=prompt)
    assert resolve(shared, zf, "a") is PasswordProblem.WRONG
    assert resolve(shared, zf, "b") is PasswordProblem.WRONG
    assert prompt.asked == ["Password for a: "] * 3 + ["Password for b: "] * 3


def test_three_wrong_answers_give_up_and_say_wrong() -> None:
    prompt = Typing("x", "y", "z")
    zf = FakeZip({"a": b"secret"})
    assert resolve(pool(prompt=prompt), zf, "a") is PasswordProblem.WRONG
    assert len(prompt.asked) == 3


def test_an_empty_answer_stops_all_further_prompting() -> None:
    zf = FakeZip({"a": b"s", "b": b"s"})
    prompt = Typing("")
    shared = pool(prompt=prompt)
    assert resolve(shared, zf, "a") is PasswordProblem.MISSING
    assert resolve(shared, zf, "b") is PasswordProblem.MISSING
    assert len(prompt.asked) == 1


def test_end_of_input_counts_as_an_empty_answer() -> None:
    zf = FakeZip({"a": b"s"})
    assert resolve(pool(prompt=Typing(None)), zf, "a") is PasswordProblem.MISSING


def test_problem_wording() -> None:
    assert PasswordProblem.WRONG.text == "wrong password"
    assert PasswordProblem.CORRUPT.text == "corrupt data, or the password is wrong"
    assert PasswordProblem.MISSING.text.startswith("password required")


def test_verifier_collision_does_not_hide_correct_password() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", encryption=ZIP_CRYPTO, compression=8) as archive:
        archive.setpassword(b"correct")
        archive.writestr("file.txt", b"payload")
    with ZipFile(buffer) as archive:
        collision = next(
            str(index).encode()
            for index in range(20000)
            if archive.check_password(str(index).encode()).ok
        )
        shared = pool(collision, b"correct")
        assert shared.resolve(archive, archive.infolist()[0]) == b"correct"
