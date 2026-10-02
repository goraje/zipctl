"""Load and dump :class:`ExtractPolicy` as plain JSON-style data.

The format maps one to one onto the policy's fields, so ``policy_to_json`` of
the default policy is a complete, self-documenting starting file.  Loading is
strict: unknown fields, wrong types and out-of-range values are all reported,
together, in a single :class:`PolicyConfigError`.
"""

from __future__ import annotations

import difflib
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, NoReturn, TypeVar, cast

from typing_extensions import override

from zipctl.zipfile.extract import (
    ExtractPolicy,
    ExtractPolicyRule,
    OverwritePolicy,
    ViolationAction,
)

__all__ = [
    "POLICY_FORMAT_VERSION",
    "PolicyConfigError",
    "PolicyIssue",
    "policy_from_json",
    "policy_from_mapping",
    "policy_to_json",
    "policy_to_mapping",
]

POLICY_FORMAT_VERSION = 1

_E = TypeVar("_E", bound=Enum)


@dataclass(frozen=True)
class PolicyIssue:
    """One problem found in a policy document.

    ``path`` locates it (``max_member_size.value``); it is empty for problems
    with the document as a whole.
    """

    path: str
    message: str

    @override
    def __str__(self) -> str:
        return f"{self.path or '<policy>'}: {self.message}"


class PolicyConfigError(ValueError):
    """Raised when a policy document is invalid; lists every problem found."""

    def __init__(self, issues: list[PolicyIssue]) -> None:
        self.issues: tuple[PolicyIssue, ...] = tuple(issues)
        super().__init__("\n".join(str(issue) for issue in self.issues))


class _Invalid:
    """Sentinel for a value that failed validation (the issue is recorded)."""


_INVALID = _Invalid()

# What a field parser can produce; ``_Invalid`` means the issue was recorded.
_Value = bool | int | float | Path | Enum | frozenset[str] | None
_Parser = Callable[[object, str, list[PolicyIssue]], _Value | _Invalid]
# A policy field as JSON data.
_Json = str | int | float | bool | None | list[str] | dict[str, "_Json"]


def _kind(value: object) -> str:
    """Name *value*'s type the way JSON does."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (list, tuple, set, frozenset)):
        return "list"
    if isinstance(value, Mapping):
        return "object"
    return type(value).__name__


def _bad(issues: list[PolicyIssue], path: str, message: str) -> _Invalid:
    issues.append(PolicyIssue(path, message))
    return _INVALID


def _expected(
    issues: list[PolicyIssue], path: str, expected: str, value: object
) -> _Invalid:
    return _bad(issues, path, f"expected {expected}, got {_kind(value)}")


def _boolean(value: object, path: str, issues: list[PolicyIssue]) -> bool | _Invalid:
    if isinstance(value, bool):
        return value
    return _expected(issues, path, "boolean", value)


def _optional_limit(
    value: object, path: str, issues: list[PolicyIssue]
) -> int | None | _Invalid:
    """A non-negative integer limit, or ``None`` for no limit."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        return _expected(issues, path, "integer or null", value)
    if value < 0:
        return _bad(issues, path, f"must not be negative, got {value}")
    return value


def _optional_ratio(
    value: object, path: str, issues: list[PolicyIssue]
) -> float | None | _Invalid:
    """A positive, finite compression ratio, or ``None`` for no limit."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return _expected(issues, path, "number or null", value)
    try:
        ratio = float(value)
    except OverflowError:
        return _bad(issues, path, "number is too large")
    if not math.isfinite(ratio):
        return _bad(issues, path, "must be a finite number")
    if ratio <= 0:
        return _bad(issues, path, f"must be greater than zero, got {value}")
    return ratio


def _enum(
    enum_type: type[_E],
) -> Callable[[object, str, list[PolicyIssue]], _E | _Invalid]:
    # Enum.value is Any in typeshed
    choices = ", ".join(repr(member.value) for member in enum_type)  # pyright: ignore[reportAny]

    def parse(value: object, path: str, issues: list[PolicyIssue]) -> _E | _Invalid:
        if not isinstance(value, str):
            return _expected(issues, path, f"a string ({choices})", value)
        try:
            return enum_type(value)
        except ValueError:
            return _bad(issues, path, f"expected one of {choices}; got {value!r}")

    return parse


_EXTENSION = re.compile(r"(\.[^./\\]+)+")


def _extension_set(
    value: object, path: str, issues: list[PolicyIssue]
) -> frozenset[str] | None | _Invalid:
    """A set of lower-cased extensions such as ``.tar.gz``; ``null`` disables it."""
    if value is None:
        return None
    if not isinstance(value, (list, tuple, set, frozenset)):
        return _expected(issues, path, "list of strings or null", value)
    extensions: set[str] = set()
    ok = True
    for index, item in enumerate(cast("Iterable[object]", value)):
        item_path = f"{path}[{index}]"
        if not isinstance(item, str):
            _expected(issues, item_path, "string", item)
            ok = False
        elif item != "" and not _EXTENSION.fullmatch(item):
            _bad(
                issues,
                item_path,
                "expected an extension like '.txt' or '.tar.gz' "
                f"(or '' for no extension), got {item!r}",
            )
            ok = False
        else:
            extensions.add(item.lower())
    return frozenset(extensions) if ok else _INVALID


def _optional_path(
    value: object, path: str, issues: list[PolicyIssue]
) -> Path | None | _Invalid:
    if value is None:
        return None
    if not isinstance(value, str):
        return _expected(issues, path, "string or null", value)
    if not value:
        return _bad(issues, path, "must not be empty")
    if "\x00" in value:
        return _bad(issues, path, "must not contain NUL characters")
    return Path(value)


# field name -> (parser, may be wrapped in a per-rule {"value", "on_violation"})
_FIELDS: dict[str, tuple[_Parser, bool]] = {
    "destination_root": (_optional_path, False),
    "allow_absolute_paths": (_boolean, True),
    "allow_parent_traversal": (_boolean, True),
    "allow_windows_drive_paths": (_boolean, True),
    "allow_symlinks": (_boolean, True),
    "allow_special_files": (_boolean, True),
    "allow_overwrite": (_boolean, False),
    "overwrite_policy": (_enum(OverwritePolicy), False),
    "max_member_size": (_optional_limit, True),
    "max_total_uncompressed_size": (_optional_limit, True),
    "max_entries": (_optional_limit, True),
    "max_compression_ratio": (_optional_ratio, True),
    "allowed_extensions": (_extension_set, True),
    "blocked_extensions": (_extension_set, True),
    "require_utf8_names": (_boolean, True),
    "reject_duplicate_targets": (_boolean, True),
    "on_violation": (_enum(ViolationAction), False),
    "preview_only": (_boolean, False),
    "fsync_files": (_boolean, False),
}

_ACTION = _enum(ViolationAction)
_RULE_KEYS = ("value", "on_violation")


def validate_policy(policy: ExtractPolicy) -> None:
    """Validate direct construction using the same field parsers as JSON."""
    issues: list[PolicyIssue] = []
    for name, (parser, wrappable) in _FIELDS.items():
        raw = cast(object, getattr(policy, name))
        if name == "destination_root" and isinstance(raw, Path):
            raw = str(raw)
        if isinstance(raw, ExtractPolicyRule):
            raw = cast(ExtractPolicyRule[object], raw)
            if not wrappable:
                _bad(issues, name, "field does not accept a per-rule action")
                continue
            value = parser(raw.value, name, issues)
            if not isinstance(value, _Invalid):
                object.__setattr__(
                    policy,
                    name,
                    None
                    if value is None
                    else ExtractPolicyRule(value, raw.on_violation),
                )
        else:
            value = parser(raw, name, issues)
            if not isinstance(value, _Invalid):
                object.__setattr__(policy, name, value)
    custom = policy.custom_validator
    if custom is not None and not callable(custom):
        if not isinstance(custom, (list, tuple)) or not all(
            callable(item) for item in custom
        ):
            _bad(
                issues,
                "custom_validator",
                "expected a callable or sequence of callables",
            )
        else:
            object.__setattr__(policy, "custom_validator", tuple(custom))
    if issues:
        raise PolicyConfigError(issues)


def _parse_rule(
    parser: _Parser, raw: Mapping[str, object], path: str, issues: list[PolicyIssue]
) -> ExtractPolicyRule[_Value] | None | _Invalid:
    """Parse ``{"value": ..., "on_violation": ...}`` into an ExtractPolicyRule.

    A rule whose value is ``null`` (no limit) becomes plain ``None``.
    """
    ok = True
    for key in raw:
        if key not in _RULE_KEYS:
            _bad(
                issues,
                f"{path}.{key}",
                "unknown key in a rule; a rule has only 'value' and 'on_violation'",
            )
            ok = False
    if "value" not in raw:
        _bad(issues, path, "a rule object needs a 'value'")
        return _INVALID
    value = parser(raw["value"], f"{path}.value", issues)
    action: ViolationAction | None = None
    raw_action = raw.get("on_violation")
    if raw_action is not None:
        parsed = _ACTION(raw_action, f"{path}.on_violation", issues)
        if isinstance(parsed, ViolationAction):
            action = parsed
        else:
            ok = False
    if not ok or isinstance(value, _Invalid):
        return _INVALID
    if value is None:
        # No limit means nothing to act on, and the policy's types do not
        # allow a rule around None, so the rule collapses to a plain null.
        return None
    return ExtractPolicyRule(value, action)


def _unknown_field(name: str) -> str:
    if name == "custom_validator":
        return (
            "custom validators are Python callables and cannot be expressed in "
            "a policy document"
        )
    close = difflib.get_close_matches(name, _FIELDS, n=1)
    if close:
        return f"unknown field; did you mean {close[0]!r}?"
    return f"unknown field; valid fields: {', '.join(_FIELDS)}"


def policy_from_mapping(
    data: Mapping[str, object], base: ExtractPolicy | None = None
) -> ExtractPolicy:
    """Build an :class:`ExtractPolicy` from JSON-style *data*.

    Only the fields present in *data* are set; the rest keep the values of
    *base* (the default policy when omitted), so documents can be layered by
    passing the result of one load as the *base* of the next.  Extensions are
    lower-cased, matching how extraction compares them.

    Raises:
        PolicyConfigError: If *data* is not a valid policy document.  The
            error lists every problem, not just the first.
    """
    return _from_document(data, base)


def _from_document(data: object, base: ExtractPolicy | None) -> ExtractPolicy:
    """Build a policy from *data*, which may be any decoded JSON value."""
    if not isinstance(data, Mapping):
        raise PolicyConfigError(
            [PolicyIssue("", f"expected an object, got {_kind(data)}")]
        )
    issues: list[PolicyIssue] = []
    # Each value was validated against its field; ``replace`` takes them as-is.
    values: dict[str, Any] = {}  # pyright: ignore[reportExplicitAny]
    for name, raw in cast("Mapping[object, object]", data).items():
        if name == "version":
            if (
                isinstance(raw, bool)
                or not isinstance(raw, int)
                or raw != POLICY_FORMAT_VERSION
            ):
                _bad(
                    issues,
                    "version",
                    f"unsupported policy format version {raw!r}; "
                    f"this release reads version {POLICY_FORMAT_VERSION}",
                )
        elif not isinstance(name, str) or name not in _FIELDS:
            _bad(issues, str(name), _unknown_field(str(name)))
        else:
            parser, wrappable = _FIELDS[name]
            value: _Value | ExtractPolicyRule[_Value] | _Invalid
            if wrappable and isinstance(raw, Mapping):
                value = _parse_rule(
                    parser, cast("Mapping[str, object]", raw), name, issues
                )
            else:
                value = parser(raw, name, issues)
            if not isinstance(value, _Invalid):
                values[name] = value
    if issues:
        raise PolicyConfigError(issues)
    return replace(base if base is not None else ExtractPolicy(), **values)


def policy_from_json(text: str, base: ExtractPolicy | None = None) -> ExtractPolicy:
    """Parse the JSON document *text* into an :class:`ExtractPolicy`.

    Beyond what :func:`policy_from_mapping` checks, duplicate object keys
    (which ``json`` would silently collapse) and ``NaN``/``Infinity`` are
    rejected.

    Raises:
        PolicyConfigError: If *text* is not valid JSON or not a valid policy.
    """
    duplicates: list[str] = []

    def collect(pairs: list[tuple[str, object]]) -> dict[str, object]:
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen:
                duplicates.append(key)
            seen.add(key)
        return dict(pairs)

    def reject_constant(name: str) -> NoReturn:
        raise ValueError(f"{name} is not allowed")

    try:
        # json.loads is typed to return Any
        data: object = json.loads(  # pyright: ignore[reportAny]
            text, object_pairs_hook=collect, parse_constant=reject_constant
        )
    except json.JSONDecodeError as exc:
        raise PolicyConfigError(
            [
                PolicyIssue(
                    "",
                    f"invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}",
                )
            ]
        ) from None
    except ValueError as exc:
        raise PolicyConfigError([PolicyIssue("", f"invalid JSON: {exc}")]) from None
    if duplicates:
        raise PolicyConfigError(
            [PolicyIssue(key, "duplicate key in a JSON object") for key in duplicates]
        )
    return _from_document(data, base)


def _dump(value: _Value | ExtractPolicyRule[_Value]) -> _Json:
    if isinstance(value, ExtractPolicyRule):
        rule: dict[str, _Json] = {"value": _dump(value.value)}
        if value.on_violation is not None:
            rule["on_violation"] = value.on_violation.value
        return rule
    if isinstance(value, Enum):
        return cast("str", value.value)  # Enum.value is Any
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    return value


# The document is JSON data that callers index into freely, so it stays ``Any``.
def policy_to_mapping(policy: ExtractPolicy) -> dict[str, Any]:  # pyright: ignore[reportExplicitAny]
    """Return *policy* as JSON-style data that :func:`policy_from_mapping` reads.

    Raises:
        PolicyConfigError: If *policy* has a custom validator, which cannot be
            serialised.
    """
    if policy.custom_validator is not None:
        raise PolicyConfigError(
            [PolicyIssue("custom_validator", _unknown_field("custom_validator"))]
        )
    document: dict[str, _Json] = {"version": POLICY_FORMAT_VERSION}
    for name in _FIELDS:
        document[name] = _dump(getattr(policy, name))  # pyright: ignore[reportAny]
    return document


def policy_to_json(policy: ExtractPolicy, *, indent: int | None = 2) -> str:
    """Return *policy* as a JSON document (see :func:`policy_to_mapping`)."""
    return json.dumps(policy_to_mapping(policy), indent=indent)
