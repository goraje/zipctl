"""The JSON encryption spec: rules whose passwords are references, not values."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from ziplet.cli.commands.helpers.encryption.plan import EncryptionPlan, Rule
from ziplet.cli.commands.helpers.passwords.sources import (
    PasswordReaders,
    password_bytes,
)
from ziplet.cli.commands.helpers.selection import glob_matcher
from ziplet.cli.errors import CliError, UsageError
from ziplet.cli.methods import ENCRYPTION_METHODS, METHOD_CHOICES
from ziplet.cli.output import did_you_mean, printable

_SPEC_KEYS = ("version", "default", "rules")
_RULE_KEYS = ("match", "method", "password")
_DEFAULT_KEYS = ("method", "password")
_REFERENCES = ("env", "file", "prompt", "stdin")


class _Issues:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, path: str, message: str) -> None:
        self.items.append(f"{path or '<spec>'}: {message}")


def _check_keys(
    data: dict[str, Any], known: Sequence[str], path: str, issues: _Issues
) -> None:
    for key in data:
        if key not in known:
            issues.add(path, f"unknown key {key!r}{did_you_mean(key, known)}")


def _reference(
    data: Any,
    path: str,
    readers: PasswordReaders,
    issues: _Issues,
    stdin_uses: list[str],
) -> tuple[bytes | None, str | None]:
    """Resolve a password reference to ``(password, prompt_label)``."""
    if not isinstance(data, dict):
        issues.add(path, 'expected an object like {"env": "NAME"}')
        return None, None
    if "value" in data or "password" in data:
        issues.add(
            path, "inline passwords are not allowed; use env, file, prompt or stdin"
        )
        return None, None
    if len(data) != 1 or next(iter(data)) not in _REFERENCES:
        issues.add(path, f"expected exactly one of: {', '.join(_REFERENCES)}")
        return None, None
    ((kind, value),) = data.items()
    if kind == "stdin":
        if value is not True:
            issues.add(f"{path}.stdin", "must be true")
            return None, None
        if stdin_uses:
            issues.add(path, "standard input can only be used by one password")
            return None, None
        stdin_uses.append(path)
        try:
            return readers.stdin(), None
        except CliError as exc:
            issues.add(path, exc.message)
            return None, None
    if not isinstance(value, str) or not value:
        issues.add(f"{path}.{kind}", "expected a non-empty string")
        return None, None
    if kind == "prompt":
        return None, value
    if kind == "env":
        text = readers.env.get(value)
        if not text:
            issues.add(
                f"{path}.env", f"environment variable {value} is not set or is empty"
            )
            return None, None
        return password_bytes(text), None
    try:
        return readers.file(value), None
    except CliError as exc:
        issues.add(f"{path}.file", exc.message)
        return None, None


def _rule(
    data: Any,
    path: str,
    readers: PasswordReaders,
    issues: _Issues,
    stdin_uses: list[str],
    *,
    is_default: bool,
) -> Rule | None:
    if not isinstance(data, dict):
        issues.add(path, "expected an object")
        return None
    _check_keys(data, _DEFAULT_KEYS if is_default else _RULE_KEYS, path, issues)
    pattern: str | None = None
    if not is_default:
        pattern = data.get("match")
        if not isinstance(pattern, str) or not pattern:
            issues.add(f"{path}.match", "required: a non-empty pattern string")
            return None
        try:
            glob_matcher(pattern)
        except CliError as exc:
            issues.add(f"{path}.match", exc.message)
            return None
    name = data.get("method")
    if not isinstance(name, str) or name not in ENCRYPTION_METHODS:
        issues.add(f"{path}.method", f"required: one of {METHOD_CHOICES}")
        return None
    method = ENCRYPTION_METHODS[name]
    if not method.is_encrypted:
        if "password" in data:
            issues.add(f"{path}.password", 'not allowed with method "none"')
        return Rule(pattern, method)
    if "password" not in data:
        issues.add(f"{path}.password", "required for an encrypting method")
        return None
    password, prompt = _reference(
        data["password"], f"{path}.password", readers, issues, stdin_uses
    )
    if password is None and prompt is None:
        return None
    hint = None
    if prompt is not None:
        hint = (
            f"the password for {printable(pattern) if pattern else 'the default rule'} "
            'can only be typed at a terminal; use an {"env": ...}, {"file": ...} or '
            '{"stdin": true} reference in the spec to script it'
        )
    return Rule(pattern, method, password=password, prompt=prompt, hint=hint)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    dupes = sorted({key for key in keys if keys.count(key) > 1})
    if dupes:
        raise ValueError(f"duplicate key {dupes[0]!r} in a JSON object")
    return dict(pairs)


def plan_from_spec(text: str, origin: str, readers: PasswordReaders) -> EncryptionPlan:
    """Parse an encryption spec; every problem is reported together."""
    where = f"invalid encryption spec ({printable(origin)})"
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicates)
    except ValueError as exc:
        raise UsageError(where, (printable(f"not valid JSON: {exc}"),)) from None
    issues = _Issues()
    if not isinstance(data, dict):
        raise UsageError(where, ("<spec>: expected a JSON object",))
    _check_keys(data, _SPEC_KEYS, "", issues)
    if data.get("version", 1) != 1:
        issues.add("version", "unsupported; this ziplet reads version 1")
    stdin_uses: list[str] = []
    rules: list[Rule] = []
    listed = data.get("rules", [])
    if not isinstance(listed, list):
        issues.add("rules", "expected a list")
        listed = []
    seen: set[str] = set()
    for index, item in enumerate(listed):
        rule = _rule(
            item,
            f"rules[{index}]",
            readers,
            issues,
            stdin_uses,
            is_default=False,
        )
        if rule is None:
            continue
        if rule.pattern in seen:
            issues.add(f"rules[{index}].match", f"duplicate pattern {rule.pattern!r}")
        seen.add(rule.pattern or "")
        rules.append(rule)
    if "default" in data:
        default = _rule(
            data["default"],
            "default",
            readers,
            issues,
            stdin_uses,
            is_default=True,
        )
        if default is not None:
            rules.append(default)
    if not listed and "default" not in data and not issues.items:
        issues.add("", "defines no rules and no default, so nothing would be encrypted")
    if issues.items:
        raise UsageError(where, tuple(printable(item) for item in issues.items))
    return EncryptionPlan(rules)
