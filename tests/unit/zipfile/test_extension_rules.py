from __future__ import annotations

import io
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import ziplet
from ziplet import ExtractPolicy, ExtractPolicyRule, ViolationAction
from ziplet.zipfile.validators import extension_chains

BASE_POLICY = ExtractPolicy(
    max_compression_ratio=None,
    max_member_size=None,
    max_total_uncompressed_size=None,
)


def _flagged(
    names: list[str], tmp_path: Path, policy: ExtractPolicy
) -> dict[str, set[str]]:
    """Assess *names* under *policy*; return {name: violation codes}."""
    buffer = io.BytesIO()
    with ziplet.ZipFile(buffer, "w") as zf:
        for name in names:
            zf.writestr(name, b"x")
    with ziplet.ZipFile(io.BytesIO(buffer.getvalue())) as zf:
        assessment = zf.assess(tmp_path, policy)
    return {
        member.info.filename: {v.code for v in member.violations}
        for member in assessment.members
    }


def _blocked(names: list[str], tmp_path: Path, extensions: Any) -> set[str]:
    policy = replace(BASE_POLICY, blocked_extensions=extensions)
    result = _flagged(names, tmp_path, policy)
    return {name for name, codes in result.items() if "extension_blocked" in codes}


def _rejected(names: list[str], tmp_path: Path, extensions: Any) -> set[str]:
    policy = replace(BASE_POLICY, allowed_extensions=extensions)
    result = _flagged(names, tmp_path, policy)
    return {name for name, codes in result.items() if "extension_not_allowed" in codes}


# --- extension_chains ------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("a.txt", {".txt"}),
        ("a.tar.gz", {".gz", ".tar.gz"}),
        ("A.TAR.GZ", {".gz", ".tar.gz"}),
        ("a.b.c.tar.gz", {".gz", ".tar.gz", ".c.tar.gz", ".b.c.tar.gz"}),
        ("dir/sub/f.tar.gz", {".gz", ".tar.gz"}),
        ("archive.tar.gz/", {".gz", ".tar.gz"}),
        ("my.report v2.txt", {".txt", ".report v2.txt"}),
        ("README", {""}),
        ("dir/README", {""}),
        (".bashrc", {""}),
        (".gz", {""}),
        (".tar.gz", {".gz"}),
        ("x.", {""}),
        ("a.tar.", {""}),
        ("...", {""}),
        ("", {""}),
    ],
)
def test_extension_chains(name: str, expected: set[str]) -> None:
    assert extension_chains(name) == frozenset(expected)


def test_extension_chains_ignore_directories_named_like_extensions() -> None:
    assert extension_chains("logs.tar/data") == frozenset({""})
    assert extension_chains("logs.tar/data.gz") == frozenset({".gz"})


NAMES = [
    "a.txt",
    "a.TXT",
    "a.tar.gz",
    "A.TAR.GZ",
    "a.b.c.tar.gz",
    "x.gz",
    "x.tar",
    "README",
    ".bashrc",
    ".gz",
    "dir/f.exe",
    "dir.d/f",
    "dir.d/f.md",
    "my.report v2.txt",
    "tool.EXE",
    "a.tar.gz/",
    "noext",
    "file.min.js",
    "x.y",
    "q.zip.tar.gz",
]
SINGLE_DOT_ENTRIES = ["", ".txt", ".gz", ".tar", ".exe", ".md", ".js", ".zip", ".y"]


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("entry", SINGLE_DOT_ENTRIES)
def test_single_dot_entries_match_exactly_as_the_last_suffix_did(
    name: str, entry: str
) -> None:
    """Behaviour that was already defined must not change."""
    old_style = Path(name).suffix.lower() == entry
    assert (entry in extension_chains(name)) == old_style


# --- blocked_extensions ----------------------------------------------------


def test_blocked_compound_extension_matches_compound_names_only(tmp_path: Path) -> None:
    names = [
        "x.tar.gz",
        "X.TAR.GZ",
        "dir/y.tar.gz",
        "x.gz",
        "x.tar",
        "tar.gz",
        ".tar.gz",
    ]
    assert _blocked(names, tmp_path, frozenset({".tar.gz"})) == {
        "x.tar.gz",
        "X.TAR.GZ",
        "dir/y.tar.gz",
    }


def test_blocked_single_extension_still_matches_compound_names(tmp_path: Path) -> None:
    names = ["x.tar.gz", "x.gz", "x.tar", "x.txt"]
    assert _blocked(names, tmp_path, frozenset({".gz"})) == {"x.tar.gz", "x.gz"}


def test_blocked_empty_entry_means_no_extension(tmp_path: Path) -> None:
    names = ["README", ".bashrc", "x.txt", "x."]
    assert _blocked(names, tmp_path, frozenset({""})) == {"README", ".bashrc", "x."}


def test_blocked_none_disables_the_rule(tmp_path: Path) -> None:
    assert _blocked(["x.exe", "x.tar.gz"], tmp_path, None) == set()


def test_blocked_accepts_any_collection_a_python_caller_might_pass(
    tmp_path: Path,
) -> None:
    for extensions in ([".exe"], (".exe",), {".exe"}):
        assert _blocked(["a.exe", "a.txt"], tmp_path, extensions) == {"a.exe"}


# --- allowed_extensions ----------------------------------------------------


def test_allowed_compound_extension(tmp_path: Path) -> None:
    names = ["x.tar.gz", "x.gz", "README", ".bashrc", "x.zip", "x.tar"]
    rejected = _rejected(names, tmp_path, frozenset({".tar.gz", ""}))
    assert rejected == {"x.gz", "x.zip", "x.tar"}


def test_allowed_single_extension_still_admits_compound_names(tmp_path: Path) -> None:
    names = ["x.tar.gz", "x.gz", "x.tar", "README"]
    assert _rejected(names, tmp_path, frozenset({".gz"})) == {"x.tar", "README"}


def test_allowed_empty_set_rejects_everything(tmp_path: Path) -> None:
    assert _rejected(["a.txt", "README"], tmp_path, frozenset()) == {"a.txt", "README"}


def test_allowed_none_disables_the_rule(tmp_path: Path) -> None:
    assert _rejected(["a.exe", "README"], tmp_path, None) == set()


def test_allowed_accepts_any_collection_a_python_caller_might_pass(
    tmp_path: Path,
) -> None:
    for extensions in ([".txt"], (".txt",), {".txt"}):
        assert _rejected(["a.txt", "a.exe"], tmp_path, extensions) == {"a.exe"}


# --- rule actions and end-to-end -------------------------------------------


def test_rule_wrapper_controls_the_action_for_compound_extensions(
    tmp_path: Path,
) -> None:
    buffer = io.BytesIO()
    with ziplet.ZipFile(buffer, "w") as zf:
        zf.writestr("x.tar.gz", b"x")
    policy = replace(
        BASE_POLICY,
        blocked_extensions=ExtractPolicyRule(
            frozenset({".tar.gz"}), ViolationAction.SKIP
        ),
    )
    with ziplet.ZipFile(io.BytesIO(buffer.getvalue())) as zf:
        member = zf.assess(tmp_path, policy).members[0]
    (violation,) = member.violations
    assert violation.code == "extension_blocked"
    assert violation.action == ViolationAction.SKIP


def test_compound_extension_rule_from_json_drives_real_extraction(
    tmp_path: Path,
) -> None:
    policy = ziplet.policy_from_json(
        '{"blocked_extensions": [".tar.gz"], "on_violation": "skip",'
        ' "max_compression_ratio": null}'
    )
    buffer = io.BytesIO()
    with ziplet.ZipFile(buffer, "w") as zf:
        zf.writestr("keep.gz", b"1")
        zf.writestr("drop.tar.gz", b"2")
        zf.writestr("keep.txt", b"3")
    with ziplet.ZipFile(io.BytesIO(buffer.getvalue())) as zf:
        result = zf.extractall(tmp_path, policy=policy)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["keep.gz", "keep.txt"]
    assert (result.extracted_count, result.skipped_count) == (2, 1)
