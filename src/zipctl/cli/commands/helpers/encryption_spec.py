"""The JSON encryption spec: rules whose passwords are references, not values."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace
from typing import cast

from zipctl.cli.commands.helpers.encryption_plan import EncryptionPlan, Rule
from zipctl.cli.commands.helpers.passwords import (
    PasswordReaders,
    password_bytes,
)
from zipctl.cli.commands.helpers.selection import glob_matcher
from zipctl.cli.errors import CliError, UsageError
from zipctl.cli.methods import ENCRYPTION_METHODS, METHOD_CHOICES
from zipctl.cli.output import did_you_mean, printable

_SPEC_KEYS = ("version", "default", "rules")
_RULE_KEYS = ("match", "method", "password")
_DEFAULT_KEYS = ("method", "password")
_REFERENCES = ("env", "file", "prompt", "stdin")


class _Issues:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, path: str, message: str) -> None:
        self.items.append(f"{path or '<spec>'}: {message}")


def _as_object(data: object) -> dict[str, object] | None:
    """*data* as a JSON object, whose keys ``json.loads`` makes strings."""
    return cast("dict[str, object]", data) if isinstance(data, dict) else None


def _check_keys(
    data: dict[str, object], known: Sequence[str], path: str, issues: _Issues
) -> None:
    for key in data:
        if key not in known:
            issues.add(path, f"unknown key {key!r}{did_you_mean(key, known)}")


def _reference_entry(
    data: object, path: str, issues: _Issues
) -> tuple[str, object] | None:
    """The ``(kind, value)`` a password reference names, or ``None`` if malformed."""
    reference = _as_object(data)
    if reference is None:
        issues.add(path, 'expected an object like {"env": "NAME"}')
        return None
    if "value" in reference or "password" in reference:
        issues.add(
            path, "inline passwords are not allowed; use env, file, prompt or stdin"
        )
        return None
    if len(reference) != 1 or next(iter(reference)) not in _REFERENCES:
        issues.add(path, f"expected exactly one of: {', '.join(_REFERENCES)}")
        return None
    ((kind, value),) = reference.items()
    return kind, value


# A password reference to read once the whole spec is known to be valid.
_Pending = tuple[Rule, str, str, str]  # rule, path, kind, value


def _reference(
    data: object, path: str, issues: _Issues, stdin_uses: list[str]
) -> tuple[str, str] | None:
    """Check a password reference without reading it; ``(kind, value)`` or ``None``."""
    entry = _reference_entry(data, path, issues)
    if entry is None:
        return None
    kind, value = entry
    if kind == "stdin":
        if value is not True:
            issues.add(f"{path}.stdin", "must be true")
            return None
        if stdin_uses:
            issues.add(path, "standard input can only be used by one password")
            return None
        stdin_uses.append(path)
        return kind, ""
    if not isinstance(value, str) or not value:
        issues.add(f"{path}.{kind}", "expected a non-empty string")
        return None
    return kind, value


def _read_reference(
    kind: str, value: str, path: str, readers: PasswordReaders, issues: _Issues
) -> bytes | None:
    """Read the password a checked reference names; ``None`` if it cannot."""
    try:
        if kind == "stdin":
            return readers.stdin()
        if kind == "file":
            return readers.file(value)
    except CliError as exc:
        issues.add(path if kind == "stdin" else f"{path}.{kind}", exc.message)
        return None
    text = readers.env.get(value)
    if not text:
        issues.add(
            f"{path}.env", f"environment variable {value} is not set or is empty"
        )
        return None
    return password_bytes(text)


def _match_pattern(fields: dict[str, object], path: str, issues: _Issues) -> str | None:
    """The rule's ``match`` glob, or ``None`` if it is missing or invalid."""
    given = fields.get("match")
    if not isinstance(given, str) or not given:
        issues.add(f"{path}.match", "required: a non-empty pattern string")
        return None
    try:
        glob_matcher(given)
    except CliError as exc:
        issues.add(f"{path}.match", exc.message)
        return None
    return given


def _rule(
    data: object,
    path: str,
    issues: _Issues,
    stdin_uses: list[str],
    pending: list[_Pending],
    *,
    is_default: bool,
) -> Rule | None:
    fields = _as_object(data)
    if fields is None:
        issues.add(path, "expected an object")
        return None
    _check_keys(fields, _DEFAULT_KEYS if is_default else _RULE_KEYS, path, issues)
    pattern: str | None = None
    if not is_default:
        pattern = _match_pattern(fields, path, issues)
        if pattern is None:
            return None
    name = fields.get("method")
    if not isinstance(name, str) or name not in ENCRYPTION_METHODS:
        issues.add(f"{path}.method", f"required: one of {METHOD_CHOICES}")
        return None
    method = ENCRYPTION_METHODS[name]
    if not method.is_encrypted:
        if "password" in fields:
            issues.add(f"{path}.password", 'not allowed with method "none"')
        return Rule(pattern, method)
    if "password" not in fields:
        issues.add(f"{path}.password", "required for an encrypting method")
        return None
    reference = _reference(fields["password"], f"{path}.password", issues, stdin_uses)
    if reference is None:
        return None
    kind, value = reference
    if kind != "prompt":
        rule = Rule(pattern, method)
        pending.append((rule, f"{path}.password", kind, value))
        return rule
    hint = (
        f"the password for {printable(pattern) if pattern else 'the default rule'} "
        'can only be typed at a terminal; use an {"env": ...}, {"file": ...} or '
        '{"stdin": true} reference in the spec to script it'
    )
    return Rule(pattern, method, prompt=value, hint=hint)


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    dupes = sorted({key for key in keys if keys.count(key) > 1})
    if dupes:
        raise ValueError(f"duplicate key {dupes[0]!r} in a JSON object")
    return dict(pairs)


def _rule_items(data: dict[str, object], issues: _Issues) -> list[object]:
    given = data.get("rules", [])
    if isinstance(given, list):
        return cast("list[object]", given)
    issues.add("rules", "expected a list")
    return []


def _list_rules(
    items: list[object],
    issues: _Issues,
    stdin_uses: list[str],
    pending: list[_Pending],
) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        rule = _rule(
            item,
            f"rules[{index}]",
            issues,
            stdin_uses,
            pending,
            is_default=False,
        )
        if rule is None:
            continue
        if rule.pattern in seen:
            issues.add(f"rules[{index}].match", f"duplicate pattern {rule.pattern!r}")
        seen.add(rule.pattern or "")
        rules.append(rule)
    return rules


def plan_from_spec(text: str, origin: str, readers: PasswordReaders) -> EncryptionPlan:
    """Parse an encryption spec; every problem is reported together."""
    where = f"invalid encryption spec ({printable(origin)})"
    try:
        # json.loads is typed to return Any
        document: object = json.loads(text, object_pairs_hook=_no_duplicates)  # pyright: ignore[reportAny]
    except ValueError as exc:
        raise UsageError(where, (printable(f"not valid JSON: {exc}"),)) from None
    issues = _Issues()
    data = _as_object(document)
    if data is None:
        raise UsageError(where, ("<spec>: expected a JSON object",))
    _check_keys(data, _SPEC_KEYS, "", issues)
    version = data.get("version", 1)
    if isinstance(version, bool) or version != 1 or not isinstance(version, int):
        issues.add("version", "unsupported; this zipctl reads version 1")
    stdin_uses: list[str] = []
    pending: list[_Pending] = []
    listed = _rule_items(data, issues)
    rules = _list_rules(listed, issues, stdin_uses, pending)
    if "default" in data:
        default = _rule(
            data["default"],
            "default",
            issues,
            stdin_uses,
            pending,
            is_default=True,
        )
        if default is not None:
            rules.append(default)
    if not listed and "default" not in data and not issues.items:
        issues.add("", "defines no rules and no default, so nothing would be encrypted")
    if not issues.items:
        # Only a valid spec gets to read files, the environment or stdin.
        found = {
            rule: _read_reference(kind, value, path, readers, issues)
            for rule, path, kind, value in pending
        }
        rules = [
            replace(rule, password=found[rule]) if rule in found else rule
            for rule in rules
        ]
    if issues.items:
        raise UsageError(where, tuple(printable(item) for item in issues.items))
    return EncryptionPlan(rules)
