from __future__ import annotations

import dataclasses
import io
import json
import re
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

import ziplet
from ziplet import (
    ExtractPolicy,
    ExtractPolicyRule,
    OverwritePolicy,
    PolicyConfigError,
    ViolationAction,
    policy_from_json,
    policy_from_mapping,
    policy_to_json,
    policy_to_mapping,
)
from ziplet.zipfile import policy_config
from ziplet.zipfile.validators import extension_chains


def _issues(data: Any) -> dict[str, str]:
    """Load *data*, expecting failure, and return {path: message}."""
    with pytest.raises(PolicyConfigError) as excinfo:
        policy_from_mapping(data)
    return {issue.path: issue.message for issue in excinfo.value.issues}


def _issue_list(data: Any) -> list[tuple[str, str]]:
    with pytest.raises(PolicyConfigError) as excinfo:
        policy_from_mapping(data)
    return [(issue.path, issue.message) for issue in excinfo.value.issues]


# --- the format tracks the dataclass -------------------------------------


def test_every_policy_field_is_covered_by_the_format() -> None:
    """A new ExtractPolicy field must be added to the format (or excluded)."""
    fields = {f.name for f in dataclasses.fields(ExtractPolicy)}
    assert fields - {"custom_validator"} == set(policy_config._FIELDS)


def test_default_policy_round_trips_and_empty_document_is_the_default() -> None:
    assert policy_from_mapping({}) == ExtractPolicy()
    assert policy_from_mapping(policy_to_mapping(ExtractPolicy())) == ExtractPolicy()
    assert policy_from_json("{}") == ExtractPolicy()


FULL_POLICY = ExtractPolicy(
    destination_root=Path("out/root"),
    allow_absolute_paths=True,
    allow_parent_traversal=ExtractPolicyRule(False, ViolationAction.ERROR),
    allow_windows_drive_paths=ExtractPolicyRule(True),
    allow_symlinks=True,
    allow_special_files=ExtractPolicyRule(False, ViolationAction.WARN),
    allow_overwrite=True,
    overwrite_policy=OverwritePolicy.RENAME,
    max_member_size=ExtractPolicyRule(1024, ViolationAction.SKIP),
    max_total_uncompressed_size=None,
    max_entries=ExtractPolicyRule(250, ViolationAction.WARN),
    max_compression_ratio=ExtractPolicyRule(12.5, ViolationAction.ERROR),
    allowed_extensions=frozenset({".txt", ".md", ""}),
    blocked_extensions=ExtractPolicyRule(
        frozenset({".exe", ".dll"}), ViolationAction.ERROR
    ),
    require_utf8_names=ExtractPolicyRule(False, ViolationAction.SKIP),
    reject_duplicate_targets=False,
    on_violation=ViolationAction.SKIP,
    preview_only=True,
    fsync_files=False,
)


def test_fully_customised_policy_round_trips_through_mapping_and_json() -> None:
    assert policy_from_mapping(policy_to_mapping(FULL_POLICY)) == FULL_POLICY
    assert policy_from_json(policy_to_json(FULL_POLICY)) == FULL_POLICY
    assert policy_from_json(policy_to_json(FULL_POLICY, indent=None)) == FULL_POLICY


def test_dump_is_plain_json_data_with_stable_ordering() -> None:
    mapping = policy_to_mapping(FULL_POLICY)
    assert json.loads(json.dumps(mapping)) == mapping
    assert mapping["version"] == 1
    assert mapping["allowed_extensions"] == ["", ".md", ".txt"]
    assert mapping["blocked_extensions"] == {
        "value": [".dll", ".exe"],
        "on_violation": "error",
    }
    assert mapping["allow_windows_drive_paths"] == {"value": True}
    assert mapping["destination_root"] == str(Path("out/root"))
    assert list(mapping)[0] == "version"
    assert policy_to_json(FULL_POLICY) == policy_to_json(FULL_POLICY)


def test_extension_sets_are_dumped_in_sorted_order() -> None:
    """Set iteration order varies between runs; the dump must not."""
    extensions = frozenset(f".e{number:02d}" for number in range(40))
    policy = ExtractPolicy(blocked_extensions=extensions)
    dumped = policy_to_mapping(policy)["blocked_extensions"]
    assert dumped == sorted(extensions)
    rule = ExtractPolicy(blocked_extensions=ExtractPolicyRule(extensions))
    assert policy_to_mapping(rule)["blocked_extensions"]["value"] == sorted(extensions)


def test_policy_with_custom_validator_cannot_be_dumped() -> None:
    policy = ExtractPolicy(custom_validator=lambda info, target: None)
    with pytest.raises(PolicyConfigError, match="custom_validator"):
        policy_to_mapping(policy)


# --- values and types -----------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("allow_symlinks", True, True),
        ("allow_overwrite", True, True),
        ("preview_only", True, True),
        ("fsync_files", False, False),
        ("max_entries", 0, 0),
        ("max_entries", None, None),
        ("max_member_size", 10**30, 10**30),
        ("max_compression_ratio", 50, 50.0),
        ("max_compression_ratio", 0.5, 0.5),
        ("max_compression_ratio", None, None),
        ("overwrite_policy", "replace", OverwritePolicy.REPLACE),
        ("on_violation", "warn", ViolationAction.WARN),
        ("destination_root", "some/dir", Path("some/dir")),
        ("destination_root", None, None),
        ("allowed_extensions", None, None),
        ("allowed_extensions", [], frozenset()),
        ("allowed_extensions", [".TXT", ".txt"], frozenset({".txt"})),
        ("blocked_extensions", ("", ".Md"), frozenset({"", ".md"})),
    ],
)
def test_valid_values_are_accepted(field: str, value: Any, expected: Any) -> None:
    policy = policy_from_mapping({field: value})
    assert getattr(policy, field) == expected
    assert type(getattr(policy, field)) is type(expected)


@pytest.mark.parametrize(
    ("field", "value", "fragment"),
    [
        ("allow_symlinks", 1, "expected boolean, got integer"),
        ("allow_symlinks", "true", "expected boolean, got string"),
        ("allow_symlinks", None, "expected boolean, got null"),
        ("preview_only", 0, "expected boolean"),
        ("allow_overwrite", {"value": True}, "expected boolean, got object"),
        ("max_entries", True, "expected integer or null, got boolean"),
        ("max_entries", 1.5, "expected integer or null, got number"),
        ("max_entries", "10", "expected integer or null, got string"),
        ("max_entries", -1, "must not be negative"),
        ("max_member_size", 5e8, "expected integer or null, got number"),
        ("max_compression_ratio", True, "expected number or null"),
        ("max_compression_ratio", "50", "expected number or null, got string"),
        ("max_compression_ratio", 0, "greater than zero"),
        ("max_compression_ratio", -2.5, "greater than zero"),
        ("max_compression_ratio", float("nan"), "finite"),
        ("max_compression_ratio", float("inf"), "finite"),
        ("max_compression_ratio", 10**400, "too large"),
        ("overwrite_policy", "overwrite", "expected one of 'error', 'skip'"),
        ("overwrite_policy", 3, "expected a string"),
        ("on_violation", "ERROR", "expected one of 'error', 'warn', 'skip'"),
        ("destination_root", "", "must not be empty"),
        ("destination_root", "a\x00b", "NUL"),
        ("destination_root", 5, "expected string or null"),
        ("allowed_extensions", ".txt", "expected list of strings or null"),
        ("allowed_extensions", [1], "allowed_extensions[0]"),
        ("allowed_extensions", ["txt"], "expected an extension like '.txt'"),
        ("allowed_extensions", ["."], "expected an extension like '.txt'"),
        ("allowed_extensions", [".a/b"], "expected an extension like '.txt'"),
        ("allowed_extensions", ["\\.txt"], "expected an extension like '.txt'"),
        ("blocked_extensions", ["*.exe"], "expected an extension like '.txt'"),
    ],
)
def test_invalid_values_are_rejected_with_a_useful_message(
    field: str, value: Any, fragment: str
) -> None:
    issues = _issue_list({field: value})
    assert len(issues) == 1
    path, message = issues[0]
    assert path.startswith(field)
    assert fragment in message or fragment in path


def test_compound_extensions_are_accepted_and_lower_cased() -> None:
    policy = policy_from_mapping({"blocked_extensions": [".tar.GZ", ".min.js", ".gz"]})
    assert policy.blocked_extensions == frozenset({".tar.gz", ".min.js", ".gz"})


@pytest.mark.parametrize(
    "entry",
    ["txt", ".", "..", "..gz", ".tar.", ".tar..gz", ".a/b", ".a\\b", "*.exe", "tar.gz"],
)
def test_malformed_extension_entries_are_rejected(entry: str) -> None:
    issues = _issues({"blocked_extensions": [entry]})
    assert (
        "expected an extension like '.txt' or '.tar.gz'"
        in issues["blocked_extensions[0]"]
    )


def test_extension_error_paths_name_the_bad_item() -> None:
    issues = _issues({"allowed_extensions": [".ok", "bad", 7]})
    assert set(issues) == {"allowed_extensions[1]", "allowed_extensions[2]"}


def test_loaded_extensions_are_compared_the_way_validators_compare() -> None:
    """Loaded entries must be members of the chains the validators compute."""
    policy = policy_from_mapping({"allowed_extensions": [".TXT", ".Tar.GZ", ""]})
    assert policy.allowed_extensions == frozenset({".txt", ".tar.gz", ""})
    assert isinstance(policy.allowed_extensions, frozenset)
    for name, entry in [("a.TXT", ".txt"), ("a.TAR.GZ", ".tar.gz"), ("README", "")]:
        assert entry in extension_chains(name)
        assert entry in policy.allowed_extensions


# --- per-rule objects -----------------------------------------------------


def test_rule_object_and_bare_value_are_both_accepted() -> None:
    policy = policy_from_mapping(
        {
            "max_member_size": {"value": 10, "on_violation": "skip"},
            "max_entries": {"value": 5},
            "max_compression_ratio": {"value": None, "on_violation": None},
            "allow_symlinks": {"value": True, "on_violation": "warn"},
            "blocked_extensions": {"value": [".exe"], "on_violation": "error"},
        }
    )
    assert policy.max_member_size == ExtractPolicyRule(10, ViolationAction.SKIP)
    assert policy.max_entries == ExtractPolicyRule(5, None)
    assert policy.max_compression_ratio is None
    assert policy.allow_symlinks == ExtractPolicyRule(True, ViolationAction.WARN)
    assert policy.blocked_extensions == ExtractPolicyRule(
        frozenset({".exe"}), ViolationAction.ERROR
    )


def test_rule_errors_are_located_inside_the_rule() -> None:
    assert _issues({"max_member_size": {"on_violation": "skip"}}) == {
        "max_member_size": "a rule object needs a 'value'"
    }
    issues = _issues({"max_member_size": {"value": "big", "on_violation": "nope"}})
    assert set(issues) == {"max_member_size.value", "max_member_size.on_violation"}
    issues = _issues({"max_member_size": {"value": 1, "extra": 2}})
    assert set(issues) == {"max_member_size.extra"}
    assert "only 'value' and 'on_violation'" in issues["max_member_size.extra"]
    issues = _issues({"max_member_size": {"value": 1, "on_violation": 5}})
    assert "expected a string" in issues["max_member_size.on_violation"]


@pytest.mark.parametrize(
    "field",
    [
        "allow_overwrite",
        "overwrite_policy",
        "on_violation",
        "preview_only",
        "fsync_files",
        "destination_root",
    ],
)
def test_fields_that_cannot_carry_a_rule_reject_rule_objects(field: str) -> None:
    issues = _issues({field: {"value": True}})
    assert field in issues
    assert "object" in issues[field]


def test_rule_value_is_validated_like_a_bare_value() -> None:
    assert "negative" in _issues({"max_entries": {"value": -3}})["max_entries.value"]
    assert (
        "expected an extension"
        in _issues({"allowed_extensions": {"value": ["txt"]}})[
            "allowed_extensions.value[0]"
        ]
    )


# --- unknown fields, version, whole-document errors -----------------------


def test_unknown_field_suggests_the_closest_name() -> None:
    issues = _issues({"max_entires": 5})
    assert issues == {"max_entires": "unknown field; did you mean 'max_entries'?"}


def test_unknown_field_without_a_match_lists_valid_fields() -> None:
    message = _issues({"zzzzzz": 1})["zzzzzz"]
    assert message.startswith("unknown field; valid fields: ")
    assert "max_entries" in message
    assert "version" not in message.split(":", 1)[1]


def test_custom_validator_gets_a_specific_message() -> None:
    message = _issues({"custom_validator": "mod:func"})["custom_validator"]
    assert "cannot be expressed" in message


@pytest.mark.parametrize("version", [2, 0, "1", 1.0, True, None])
def test_only_format_version_one_is_accepted(version: Any) -> None:
    issues = _issues({"version": version})
    assert "unsupported policy format version" in issues["version"]


def test_version_one_is_accepted() -> None:
    assert policy_from_mapping({"version": 1}) == ExtractPolicy()


@pytest.mark.parametrize(
    ("document", "kind"),
    [([], "list"), ("{}", "string"), (None, "null"), (5, "integer"), (True, "boolean")],
)
def test_the_document_itself_must_be_an_object(document: Any, kind: str) -> None:
    assert _issues(document) == {"": f"expected an object, got {kind}"}


def test_every_problem_is_reported_at_once_in_document_order() -> None:
    issues = _issue_list(
        {
            "max_entries": "many",
            "bogus": 1,
            "allow_symlinks": "yes",
            "overwrite_policy": "nope",
            "version": 3,
        }
    )
    assert [path for path, _ in issues] == [
        "max_entries",
        "bogus",
        "allow_symlinks",
        "overwrite_policy",
        "version",
    ]


def test_error_text_lists_each_issue_on_its_own_line() -> None:
    with pytest.raises(PolicyConfigError) as excinfo:
        policy_from_mapping({"max_entries": "many", "": 1})
    lines = str(excinfo.value).splitlines()
    assert lines[0].startswith("max_entries: expected integer or null")
    assert len(lines) == 2
    assert isinstance(excinfo.value, ValueError)
    assert all(isinstance(issue, ziplet.PolicyIssue) for issue in excinfo.value.issues)


def test_a_valid_field_next_to_an_invalid_one_is_not_applied() -> None:
    with pytest.raises(PolicyConfigError):
        policy_from_mapping({"max_entries": 5, "allow_symlinks": "x"})


# --- layering ------------------------------------------------------------


def test_fields_missing_from_a_document_keep_the_base_values() -> None:
    def validator(info: Any, target: Any) -> None:
        return None

    base = ExtractPolicy(
        max_entries=7, on_violation=ViolationAction.SKIP, custom_validator=validator
    )
    policy = policy_from_mapping({"max_member_size": 99}, base=base)
    assert policy.max_member_size == 99
    assert policy.max_entries == 7
    assert policy.on_violation == ViolationAction.SKIP
    assert policy.custom_validator is validator
    assert policy_from_json('{"max_entries": null}', base=base).max_entries is None


def test_documents_layer_with_last_one_winning() -> None:
    first = policy_from_json('{"max_entries": 1, "max_member_size": 10}')
    second = policy_from_json('{"max_entries": 2}', base=first)
    assert (second.max_entries, second.max_member_size) == (2, 10)


# --- JSON text ------------------------------------------------------------


def test_json_syntax_errors_report_the_position() -> None:
    with pytest.raises(PolicyConfigError) as excinfo:
        policy_from_json('{\n  "max_entries": 5,\n}')
    assert excinfo.value.issues[0].path == ""
    # The exact wording and position differ between Python versions.
    assert re.match(
        r"invalid JSON at line [23] column \d+: ", excinfo.value.issues[0].message
    )


@pytest.mark.parametrize("text", ["", "   ", "not json", '{"a": }'])
def test_malformed_json_is_a_policy_error(text: str) -> None:
    with pytest.raises(PolicyConfigError, match="invalid JSON"):
        policy_from_json(text)


def test_duplicate_keys_are_rejected_instead_of_silently_collapsed() -> None:
    with pytest.raises(PolicyConfigError) as excinfo:
        policy_from_json('{"max_entries": 1, "max_entries": 2}')
    assert [i.path for i in excinfo.value.issues] == ["max_entries"]
    assert "duplicate key" in excinfo.value.issues[0].message


def test_duplicate_keys_inside_a_rule_are_rejected() -> None:
    text = '{"max_member_size": {"value": 1, "value": 2}}'
    with pytest.raises(PolicyConfigError, match="duplicate key"):
        policy_from_json(text)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_json_constants_are_rejected(constant: str) -> None:
    with pytest.raises(PolicyConfigError, match="not allowed"):
        policy_from_json('{"max_compression_ratio": %s}' % constant)


@pytest.mark.parametrize("text", ["[]", '"x"', "null", "3"])
def test_json_root_must_be_an_object(text: str) -> None:
    with pytest.raises(PolicyConfigError, match="expected an object"):
        policy_from_json(text)


def test_json_document_with_unicode_and_nested_rules() -> None:
    policy = policy_from_json(
        '{"destination_root": "dossier/été", '
        '"max_member_size": {"value": 1, "on_violation": "skip"}}'
    )
    assert policy.destination_root == Path("dossier/été")
    assert policy.max_member_size == ExtractPolicyRule(1, ViolationAction.SKIP)


def test_default_policy_dump_is_a_valid_starting_document() -> None:
    text = policy_to_json(ExtractPolicy())
    document = json.loads(text)
    document["max_entries"] = 50
    assert policy_from_mapping(document).max_entries == 50


# --- behaviour: a loaded policy really drives extraction -------------------


def _archive(files: dict[str, bytes]) -> io.BytesIO:
    buffer = io.BytesIO()
    with ziplet.ZipFile(buffer, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return io.BytesIO(buffer.getvalue())


def test_loaded_policy_enforces_rules_during_extraction(tmp_path: Path) -> None:
    policy = policy_from_json(
        json.dumps(
            {
                "on_violation": "skip",
                "blocked_extensions": {"value": [".exe"], "on_violation": "skip"},
                "max_member_size": {"value": 10, "on_violation": "skip"},
                "max_compression_ratio": None,
            }
        )
    )
    files = {"ok.txt": b"fine", "tool.EXE": b"x", "big.txt": b"y" * 50}
    with ziplet.ZipFile(_archive(files)) as zf:
        result = zf.extractall(tmp_path, policy=policy)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["ok.txt"]
    assert (result.extracted_count, result.skipped_count) == (1, 2)


def test_loaded_and_hand_built_policies_are_interchangeable(tmp_path: Path) -> None:
    built = ExtractPolicy(max_entries=1, on_violation=ViolationAction.SKIP)
    loaded = policy_from_json('{"max_entries": 1, "on_violation": "skip"}')
    assert loaded == built
    with ziplet.ZipFile(_archive({"a": b"1", "b": b"2"})) as zf:
        result = zf.extractall(tmp_path, policy=loaded)
    assert (result.extracted_count, result.skipped_count) == (1, 1)


def test_read_only_mappings_are_accepted() -> None:
    policy = policy_from_mapping(MappingProxyType({"max_entries": 3}))
    assert policy.max_entries == 3


def test_non_string_keys_are_reported_not_crashed_on() -> None:
    issues = _issues({1: "x"})
    assert list(issues) == ["1"]
    assert issues["1"].startswith("unknown field")


def test_loading_does_not_modify_the_input_document() -> None:
    document = {
        "allowed_extensions": [".TXT"],
        "max_member_size": {"value": 5, "on_violation": "skip"},
    }
    snapshot = json.loads(json.dumps(document))
    policy_from_mapping(document)
    assert document == snapshot


@pytest.mark.parametrize(
    "field",
    ["max_entries", "max_member_size", "max_compression_ratio", "allowed_extensions"],
)
def test_a_rule_around_null_collapses_to_null(field: str) -> None:
    """A null limit has nothing to act on, so its rule action is dropped."""
    policy = policy_from_mapping({field: {"value": None, "on_violation": "skip"}})
    assert getattr(policy, field) is None
    assert policy_from_mapping(policy_to_mapping(policy)) == policy
