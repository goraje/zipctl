"""The encryption plan: option parsing, JSON specs and rule assignment."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from typing_extensions import override

from tests.unit.cli.conftest import new_context
from zipctl.cli.commands.helpers.encryption_options import _split_protect
from zipctl.cli.commands.helpers.encryption_plan import EncryptionPlan, Rule
from zipctl.cli.commands.helpers.encryption_spec import plan_from_spec
from zipctl.cli.commands.helpers.passwords import (
    PasswordReaders,
    readers_for,
)
from zipctl.cli.context import Context
from zipctl.cli.errors import CliError
from zipctl.cli.methods import ENCRYPTION_METHODS
from zipctl.cli.output import JsonValue


@pytest.mark.parametrize(
    ("text", "split"),
    [
        ("*.txt", ("*.txt", "aes256")),
        ("*.txt=aes128", ("*.txt", "aes128")),
        ("*.txt=zipcrypto", ("*.txt", "zipcrypto")),
        ("a=b.txt", ("a=b.txt", "aes256")),  # not a method: part of the glob
        ("=aes256", ("=aes256", "aes256")),  # no glob left: keep it whole
    ],
)
def test_split_protect(text: str, split: tuple[str, str]) -> None:
    assert _split_protect(text) == split


def test_split_protect_flags_a_near_miss_method_as_a_typo() -> None:
    with pytest.raises(CliError) as caught:
        _split_protect("*.txt=aes265")
    assert caught.value.code == 2
    assert "did you mean 'aes256'" in caught.value.message


def spec(**parts: JsonValue) -> str:
    return json.dumps(parts)


def issues_of(text: str, stdin: str = "") -> tuple[str, ...]:
    with pytest.raises(CliError) as caught:
        plan_from_spec(text, "spec.json", readers_for(new_context(stdin=stdin)))
    assert caught.value.code == 2
    return caught.value.details


def test_a_valid_spec_becomes_ordered_rules_with_the_default_last(
    tmp_path: Path,
) -> None:
    secret = tmp_path / "pw"
    secret.write_text("from-file\n")
    text = spec(
        rules=[
            {"match": "*.txt", "method": "aes128", "password": {"env": "PW"}},
            {"match": "*.log", "method": "none"},
            {"match": "*.bin", "method": "aes256", "password": {"file": str(secret)}},
        ],
        default={"method": "aes256", "password": {"prompt": "the rest"}},
    )
    plan = plan_from_spec(
        text, "spec.json", readers_for(new_context({"PW": "hunter2"}))
    )
    assert [(r.pattern, r.method.name) for r in plan.rules] == [
        ("*.txt", "aes128"),
        ("*.log", "none"),
        ("*.bin", "aes256"),
        (None, "aes256"),
    ]
    assert [r.password for r in plan.rules] == [b"hunter2", None, b"from-file", None]
    assert plan.rules[-1].prompt == "the rest"


def test_every_problem_in_a_spec_is_reported_together() -> None:
    text = spec(
        version=2,
        rules=[
            {"match": "*.txt", "method": "aes999", "password": {"env": "PW"}},
            {"match": "a**", "method": "none"},
            {"match": "*.md", "method": "none", "password": {"env": "PW"}},
            {"match": "*.c", "method": "aes256", "password": {"value": "inline"}},
            {"method": "none"},
            {"match": "*.h", "method": "aes256", "pasword": {"env": "PW"}},
        ],
    )
    details = "\n".join(issues_of(text))
    for expected in (
        "version: unsupported",
        "rules[0].method: required: one of",
        "rules[1].match: invalid pattern",
        'rules[2].password: not allowed with method "none"',
        "rules[3].password: inline passwords are not allowed",
        "rules[4].match: required",
        "unknown key 'pasword' (did you mean 'password'?)",
    ):
        assert expected in details


def test_a_missing_environment_variable_is_a_spec_issue() -> None:
    text = spec(default={"method": "aes256", "password": {"env": "NOPE"}})
    assert "environment variable NOPE is not set" in "\n".join(issues_of(text))


def test_a_duplicate_pattern_is_reported() -> None:
    rule = {"match": "*.txt", "method": "none"}
    assert "duplicate pattern" in "\n".join(issues_of(spec(rules=[rule, rule])))


def test_standard_input_can_supply_only_one_password() -> None:
    ref = {"stdin": True}
    text = spec(
        rules=[
            {"match": "a", "method": "aes256", "password": ref},
            {"match": "b", "method": "aes256", "password": ref},
        ]
    )
    details = "\n".join(issues_of(text, stdin="pw\n"))
    assert "standard input can only be used by one password" in details


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("{", "not valid JSON"),
        ('{"a": 1, "a": 2}', "duplicate key 'a'"),
        ("[]", "expected a JSON object"),
        ("{}", "defines no rules and no default"),
    ],
)
def test_a_structurally_broken_spec_is_refused(text: str, fragment: str) -> None:
    assert fragment in "\n".join(issues_of(text))


def plan(*rules: Rule) -> EncryptionPlan:
    return EncryptionPlan(rules)


def test_assign_picks_the_first_matching_rule_and_the_default_catches_the_rest() -> (
    None
):
    first = Rule("*.txt", ENCRYPTION_METHODS["aes128"], password=b"1")
    second = Rule("*", ENCRYPTION_METHODS["aes256"], password=b"2")
    default = Rule(None, ENCRYPTION_METHODS["none"])
    assignment = plan(first, second, default).assign(["a.txt", "b.bin"], new_context())
    assert assignment.chosen == {"a.txt": first, "b.bin": second}
    assert assignment.methods == {
        ENCRYPTION_METHODS["aes128"],
        ENCRYPTION_METHODS["aes256"],
    }
    assert default not in assignment.chosen.values()


def test_assign_does_not_change_the_plan_so_it_can_run_twice() -> None:
    rules = plan(Rule("*.txt", ENCRYPTION_METHODS["aes256"], password=b"1"))
    assert (
        rules.assign(["a.txt"], new_context()).chosen
        == rules.assign(["a.txt"], new_context()).chosen
    )


def test_a_member_no_rule_covers_maps_to_none() -> None:
    assert (
        plan(Rule("*.txt", ENCRYPTION_METHODS["aes256"]))
        .assign(["a.txt", "b.md"], new_context())
        .chosen["b.md"]
        is None
    )


def test_a_rule_that_decides_nothing_is_an_error() -> None:
    shadowed = Rule("*.txt", ENCRYPTION_METHODS["aes128"])
    with pytest.raises(
        CliError, match=r"no member is decided by the rule for '\*\.txt'"
    ):
        plan(Rule("*", ENCRYPTION_METHODS["aes256"]), shadowed).assign(
            ["a.txt"], new_context()
        )
    with pytest.raises(CliError, match="typo'"):
        plan(Rule("typo", ENCRYPTION_METHODS["aes256"])).assign(
            ["a.txt"], new_context()
        )


def test_a_spec_reads_its_passwords_through_the_readers_it_is_given() -> None:
    readers = PasswordReaders(
        {"PW": "from env"}, lambda path: path.encode(), lambda: b"in"
    )
    text = json.dumps(
        {
            "rules": [
                {"match": "a", "method": "aes256", "password": {"file": "f.txt"}},
                {"match": "b", "method": "aes256", "password": {"env": "PW"}},
            ],
            "default": {"method": "aes256", "password": {"stdin": True}},
        }
    )
    rules = plan_from_spec(text, "spec.json", readers).rules
    assert [r.password for r in rules] == [b"f.txt", b"from env", b"in"]


def test_an_invalid_spec_reads_no_password() -> None:
    def refuse(*_: object) -> bytes:
        raise AssertionError("a password was read from an invalid spec")

    readers = PasswordReaders({}, refuse, refuse)
    text = json.dumps(
        {
            "rules": [
                {"match": "a", "method": "aes256", "password": {"file": "f.txt"}},
                {"match": "b", "method": "aes257", "password": {"env": "PW"}},
            ],
            "default": {"method": "aes256", "password": {"stdin": True}},
        }
    )
    with pytest.raises(CliError) as caught:
        plan_from_spec(text, "spec.json", readers)
    (detail,) = caught.value.details
    assert detail.startswith("rules[1].method: required: one of")


def test_a_boolean_spec_version_is_refused() -> None:
    details = issues_of(spec(version=True, default={"method": "none"}))
    assert details == ("version: unsupported; this zipctl reads version 1",)


class _Terminal(io.StringIO):
    @override
    def isatty(self) -> bool:
        return True


def test_prompted_passwords_are_asked_through_the_given_prompt() -> None:
    asked: list[str] = []

    def prompt(label: str) -> str:
        asked.append(label)
        return "typed"

    ctx = Context(_Terminal(), io.StringIO(), io.StringIO(), {}, prompt=prompt)
    rule = Rule("*", ENCRYPTION_METHODS["aes256"], prompt="Password")
    rules = plan(rule)
    assignment = rules.assign(["a.txt"], ctx)
    assert assignment.protection("a.txt", ctx).password == b"typed"
    assert assignment.protection("a.txt", ctx).password == b"typed"  # asked once
    assert asked == ["Password: ", "Confirm password: "]
