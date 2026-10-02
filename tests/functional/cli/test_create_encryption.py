"""``zipctl create``: --encryption, --protect and --encryption-spec."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typing_extensions import Unpack

from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.reports import CreateReport, ListReport, load_json
from tests.functional.cli.support import (
    END_OF_INPUT,
    HAS_PTY,
    PASSWORD,
    Result,
    RunOptions,
)
from tests.functional.cli.support import run_in_terminal as terminal
from zipctl import ZipFile
from zipctl.cli.output import JsonValue
from zipctl.zipfile.info import ZipInfo

PW = PASSWORD.encode()
ENV = {"ZIPCTL_PASSWORD": PASSWORD}
needs_pty = pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")
FILES = {
    "public/readme.txt": b"public readme",
    "public/logo.bin": bytes(range(200)),
    "secrets/db.key": b"db secret",
    "secrets/api.key": b"api secret",
    "notes.txt": b"notes",
}


@pytest.fixture
def tree(workdir: Path) -> Path:
    for name, data in FILES.items():
        path = workdir / "tree" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return workdir / "tree"


def create(
    cli: CliRunner, workdir: Path, *args: str, **kw: Unpack[RunOptions]
) -> Result:
    """``zipctl create out.zip . ARGS`` run inside the tree."""
    kw.setdefault("cwd", workdir / "tree")
    return cli("create", str(workdir / "out.zip"), ".", *args, **kw)


def infos(path: Path) -> dict[str, ZipInfo]:
    with ZipFile(path) as zf:
        return {i.filename: i for i in zf.infolist() if not i.is_dir()}


def scheme(info: ZipInfo) -> str:
    if not info.is_encrypted:
        return "none"
    strength = info.aes_extra.wz_aes_strength
    return (
        {1: "aes128", 2: "aes192", 3: "aes256"}[strength] if strength else "zipcrypto"
    )


def schemes(path: Path) -> dict[str, str]:
    return {name: scheme(info) for name, info in infos(path).items()}


def matches(cli: CliRunner, archive: Path, password: str, *members: str) -> bool:
    """True if *password* is accepted by every encrypted (selected) member."""
    result = cli(
        "check-password", "--full", str(archive), *members,
        env={"ZIPCTL_PASSWORD": password},
    )  # fmt: skip
    return result.returncode == 0


def read_all(path: Path, password: bytes) -> dict[str, bytes]:
    with ZipFile(path) as zf:
        return {
            i.filename: zf.read(i, pwd=password if i.is_encrypted else None)
            for i in zf.infolist()
            if not i.is_dir()
        }


# --- --encryption


@pytest.mark.usefixtures("tree")
@pytest.mark.parametrize("method", ["aes128", "aes192", "aes256", "zipcrypto"])
def test_encrypt_protects_every_file(
    cli: CliRunner, workdir: Path, method: str
) -> None:
    result = create(cli, workdir, "--encryption", method, env=ENV)
    assert result.returncode == 0, result
    archive = workdir / "out.zip"
    assert set(schemes(archive).values()) == {method}
    assert read_all(archive, PW) == FILES
    assert matches(cli, archive, PASSWORD)
    assert "5 encrypted" in result.stdout


@pytest.mark.usefixtures("tree")
def test_directories_carry_no_encryption(cli: CliRunner, workdir: Path) -> None:
    create(cli, workdir, "--encryption", "aes256", env=ENV)
    with ZipFile(workdir / "out.zip") as zf:
        assert all(not i.is_encrypted for i in zf.infolist() if i.is_dir())
        assert zf.namelist()[0].endswith("/")


@pytest.mark.usefixtures("tree")
def test_a_wrong_password_does_not_fit_what_was_created(
    cli: CliRunner, workdir: Path
) -> None:
    create(cli, workdir, "--encryption", "aes256", env=ENV)
    assert not matches(cli, workdir / "out.zip", "not the password")


@pytest.mark.usefixtures("tree")
def test_every_encrypted_archive_is_read_back_by_our_extract(
    cli: CliRunner, workdir: Path
) -> None:
    create(cli, workdir, "--encryption", "aes256", env=ENV)
    result = cli("extract", str(workdir / "out.zip"), "-d", str(workdir / "x"), env=ENV)
    assert result.returncode == 0, result
    assert (workdir / "x" / "secrets" / "db.key").read_bytes() == b"db secret"


@pytest.mark.usefixtures("tree")
def test_the_standard_library_cannot_read_it_without_the_password(
    cli: CliRunner, workdir: Path
) -> None:
    import zipfile

    create(cli, workdir, "--encryption", "zipcrypto", env=ENV)
    with zipfile.ZipFile(workdir / "out.zip") as zf:
        assert zf.read("notes.txt", pwd=PW) == b"notes"  # ZipCrypto only
        with pytest.raises(RuntimeError):
            zf.read("notes.txt")


@pytest.mark.usefixtures("tree")
def test_encrypt_none_is_a_plain_archive(cli: CliRunner, workdir: Path) -> None:
    result = create(cli, workdir, "--encryption", "none")
    assert result.returncode == 0, result
    assert set(schemes(workdir / "out.zip").values()) == {"none"}


@pytest.mark.usefixtures("tree")
def test_zipcrypto_is_flagged_as_legacy_and_the_flag_can_be_silenced(
    cli: CliRunner, workdir: Path
) -> None:
    loud = create(cli, workdir, "--encryption", "zipcrypto", env=ENV)
    assert "ZipCrypto is a weak legacy cipher" in loud.stderr
    quiet = create(cli, workdir, "--encryption", "zipcrypto", "--force", "-q", env=ENV)
    assert quiet.stderr == ""
    aes = create(cli, workdir, "--encryption", "aes256", "--force", env=ENV)
    assert aes.stderr == ""


@pytest.mark.usefixtures("tree")
def test_aes_version_1_exposes_the_crc_and_2_hides_it(
    cli: CliRunner, workdir: Path
) -> None:
    def crcs(*extra: str) -> set[str]:
        create(cli, workdir, "--encryption", "aes256", "--force", *extra, env=ENV)
        listing = load_json(cli("list", "--json", str(workdir / "out.zip")), ListReport)
        return {m["crc32"] for m in listing["members"] if not m["directory"]}

    assert crcs() == {"00000000"}
    assert crcs("--wz-aes-version", "2") == {"00000000"}
    assert "00000000" not in crcs("--wz-aes-version", "1")


@pytest.mark.usefixtures("tree")
@pytest.mark.parametrize(
    "extra", [[], ["--encryption", "zipcrypto"], ["--encryption", "none"]]
)
def test_aes_version_without_aes_is_a_usage_error(
    cli: CliRunner, workdir: Path, extra: list[str]
) -> None:
    result = create(cli, workdir, "--wz-aes-version", "1", *extra, env=ENV)
    assert result.returncode == 2, result
    assert "only applies to AES" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_an_unknown_method_is_a_usage_error(cli: CliRunner, workdir: Path) -> None:
    result = create(cli, workdir, "--encryption", "rot13")
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


# --- where --encryption gets its password


@pytest.mark.usefixtures("tree")
def test_the_password_can_come_from_a_file_or_standard_input(
    cli: CliRunner, workdir: Path
) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(PW + b"\n")
    assert (
        create(
            cli, workdir, "--encryption", "aes256", "--password-file", str(passfile)
        ).returncode
        == 0
    )
    assert matches(cli, workdir / "out.zip", PASSWORD)
    piped = create(
        cli,
        workdir,
        "--encryption",
        "aes256",
        "--password-stdin",
        "--force",
        stdin="other\n",
    )
    assert piped.returncode == 0, piped
    assert matches(cli, workdir / "out.zip", "other")
    assert not matches(cli, workdir / "out.zip", PASSWORD)


@pytest.mark.usefixtures("tree")
def test_a_password_that_is_not_utf8_is_kept_byte_for_byte(
    cli: CliRunner, workdir: Path
) -> None:
    raw = b"\xff\xfe binary \x80"
    passfile = workdir / "pw"
    passfile.write_bytes(raw + b"\n")
    create(cli, workdir, "--encryption", "aes256", "--password-file", str(passfile))
    assert read_all(workdir / "out.zip", raw) == FILES


@pytest.mark.usefixtures("tree")
def test_the_file_beats_the_environment(cli: CliRunner, workdir: Path) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(b"from-file\n")
    create(
        cli,
        workdir,
        "--encryption",
        "aes256",
        "--password-file",
        str(passfile),
        env=ENV,
    )
    assert matches(cli, workdir / "out.zip", "from-file")
    assert not matches(cli, workdir / "out.zip", PASSWORD)


@pytest.mark.usefixtures("tree")
def test_two_different_passwords_are_a_usage_error(
    cli: CliRunner, workdir: Path
) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(b"one\n")
    result = create(
        cli, workdir, "--encryption", "aes256", "--password-file", str(passfile),
        "--password-stdin", stdin="two\n",
    )  # fmt: skip
    assert result.returncode == 2, result
    assert "one password" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_without_a_source_or_terminal_nothing_is_written(
    cli: CliRunner, workdir: Path
) -> None:
    result = create(cli, workdir, "--encryption", "aes256")
    assert result.returncode == 2, result
    assert "no password given" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_password_options_without_encrypt_are_refused_not_ignored(
    cli: CliRunner, workdir: Path
) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(b"x\n")
    for extra in (["--password-file", str(passfile)], ["--password-stdin"]):
        result = create(cli, workdir, *extra, stdin="x\n")
        assert result.returncode == 2, result
        assert "--encryption names nothing to protect" in result.stderr
        assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_the_environment_alone_does_not_encrypt(cli: CliRunner, workdir: Path) -> None:
    assert create(cli, workdir, env=ENV).returncode == 0
    assert set(schemes(workdir / "out.zip").values()) == {"none"}


@pytest.mark.usefixtures("tree")
def test_the_password_never_appears_in_any_output(
    cli: CliRunner, workdir: Path
) -> None:
    for extra in ([], ["-v"], ["--json"]):
        result = create(
            cli, workdir, "--encryption", "aes256", "--force", *extra, env=ENV
        )
        assert PASSWORD not in result.stdout + result.stderr


# --- typing the password


@pytest.mark.usefixtures("tree")
@needs_pty
def test_a_typed_password_is_asked_for_twice(cli: CliRunner, workdir: Path) -> None:
    result, prompts = terminal(
        "create", str(workdir / "out.zip"), ".", "--encryption", "aes256",
        replies=[PASSWORD, PASSWORD],
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 2
    assert "Password: " in result.stderr
    assert "Confirm password: " in result.stderr
    assert PASSWORD not in result.stdout + result.stderr
    assert matches(cli, workdir / "out.zip", PASSWORD)


@pytest.mark.usefixtures("tree")
@needs_pty
def test_the_typed_password_is_masked_where_python_allows(workdir: Path) -> None:
    result, _ = terminal(
        "create", str(workdir / "out.zip"), ".",
        "--encryption", "aes256",
        replies=[PASSWORD, PASSWORD],
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 0, result
    if sys.version_info >= (3, 14):
        assert "*" * len(PASSWORD) in result.stderr  # pyright: ignore[reportUnreachable]  # basedpyright assumes Python 3.10
    else:
        assert "*" not in result.stderr


@pytest.mark.usefixtures("tree")
@needs_pty
def test_a_mismatch_writes_nothing(workdir: Path) -> None:
    result, prompts = terminal(
        "create", str(workdir / "out.zip"), ".", "--encryption", "aes256",
        replies=["one", "two"],
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 2, result
    assert prompts == 2
    assert "the passwords do not match" in result.stderr
    assert not (workdir / "out.zip").exists()
    assert list(workdir.glob(".zipctl-*")) == []


@pytest.mark.usefixtures("tree")
@needs_pty
@pytest.mark.parametrize(
    ("replies", "extra"),
    [
        ([""], []),
        pytest.param(
            [END_OF_INPUT],
            [],
            marks=pytest.mark.skipif(
                sys.version_info >= (3, 14), reason="Ctrl-D does not end masked input"
            ),
        ),
        (["good", ""], []),
    ],
)
def test_an_empty_answer_writes_nothing(
    workdir: Path, replies: list[str], extra: list[str]
) -> None:
    result, _ = terminal(
        "create", str(workdir / "out.zip"), ".", "--encryption", "aes256", *extra,
        replies=replies,
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 2, result
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
@needs_pty
def test_interrupting_a_prompt_exits_130_and_leaves_nothing(workdir: Path) -> None:
    result, _ = terminal(
        "create", str(workdir / "out.zip"), ".", "--encryption", "aes256",
        interrupt_at_prompt=1,
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 130, result
    assert "Traceback" not in result.stderr
    assert not (workdir / "out.zip").exists()
    assert list(workdir.glob(".zipctl-*")) == []


# --- --protect


@pytest.mark.usefixtures("tree")
@needs_pty
def test_protect_asks_for_its_own_password_and_protects_only_matches(
    cli: CliRunner, workdir: Path
) -> None:
    result, prompts = terminal(
        "create", str(workdir / "out.zip"), ".", "--protect", "secrets/**",
        replies=["vault", "vault"],
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 2
    assert "Password for secrets/**: " in result.stderr
    assert "Confirm password for secrets/**: " in result.stderr
    assert schemes(workdir / "out.zip") == {
        "public/readme.txt": "none",
        "public/logo.bin": "none",
        "secrets/db.key": "aes256",
        "secrets/api.key": "aes256",
        "notes.txt": "none",
    }
    assert read_all(workdir / "out.zip", b"vault") == FILES
    assert matches(cli, workdir / "out.zip", "vault")
    assert not matches(cli, workdir / "out.zip", PASSWORD)


@pytest.mark.usefixtures("tree")
@needs_pty
def test_each_rule_gets_a_different_password(cli: CliRunner, workdir: Path) -> None:
    result, prompts = terminal(
        "create", str(workdir / "out.zip"), ".",
        "--protect", "secrets/db.key=aes128", "--protect", "*.txt=zipcrypto",
        replies=["db-pass", "db-pass", "txt-pass", "txt-pass"],
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 4
    assert schemes(workdir / "out.zip") == {
        "public/readme.txt": "none",
        "public/logo.bin": "none",
        "secrets/db.key": "aes128",
        "secrets/api.key": "none",
        "notes.txt": "zipcrypto",
    }
    assert matches(cli, workdir / "out.zip", "db-pass", "secrets/db.key")
    assert matches(cli, workdir / "out.zip", "txt-pass", "notes.txt")
    assert not matches(cli, workdir / "out.zip", "txt-pass", "secrets/db.key")
    assert "ZipCrypto is a weak legacy cipher" in result.stderr


@pytest.mark.usefixtures("cli", "tree")
@needs_pty
def test_the_first_matching_rule_wins(workdir: Path) -> None:
    result, prompts = terminal(
        "create", str(workdir / "out.zip"), ".",
        "--protect", "secrets/api.key=none", "--protect", "secrets/**",
        replies=["vault", "vault"],
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 2
    assert schemes(workdir / "out.zip")["secrets/api.key"] == "none"
    assert schemes(workdir / "out.zip")["secrets/db.key"] == "aes256"


@pytest.mark.usefixtures("tree")
def test_protect_none_carves_a_hole_in_encrypt(cli: CliRunner, workdir: Path) -> None:
    result = create(
        cli, workdir, "--encryption", "aes256", "--protect", "public/**=none", env=ENV
    )
    assert result.returncode == 0, result
    assert schemes(workdir / "out.zip") == {
        "public/readme.txt": "none",
        "public/logo.bin": "none",
        "secrets/db.key": "aes256",
        "secrets/api.key": "aes256",
        "notes.txt": "aes256",
    }
    assert "3 encrypted" in result.stdout
    assert matches(cli, workdir / "out.zip", PASSWORD)


@pytest.mark.usefixtures("tree")
def test_only_none_rules_need_no_password_at_all(cli: CliRunner, workdir: Path) -> None:
    result = create(cli, workdir, "--protect", "public/**=none")
    assert result.returncode == 0, result
    assert set(schemes(workdir / "out.zip").values()) == {"none"}


@pytest.mark.usefixtures("tree")
def test_a_protect_password_cannot_be_scripted_so_it_says_where_to_go(
    cli: CliRunner, workdir: Path
) -> None:
    result = create(cli, workdir, "--protect", "secrets/**", env=ENV)
    assert result.returncode == 2, result
    assert "only be typed at a terminal" in result.stderr
    assert "--encryption-spec" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_a_rule_that_decides_nothing_is_an_error_before_anything_happens(
    cli: CliRunner, workdir: Path
) -> None:
    result = create(
        cli, workdir, "--encryption", "aes256", "--protect", "sercets/**=none", env=ENV
    )
    assert result.returncode == 2, result
    assert "no member is decided by the rule for 'sercets/**'" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_a_shadowed_rule_is_an_error_too(cli: CliRunner, workdir: Path) -> None:
    result = create(
        cli, workdir, "--protect", "**=none", "--protect", "secrets/**=none"
    )
    assert result.returncode == 2, result
    assert "no member is decided by the rule for 'secrets/**'" in result.stderr


@pytest.mark.usefixtures("tree")
@needs_pty
def test_no_password_is_asked_when_a_rule_matches_nothing(workdir: Path) -> None:
    result, prompts = terminal(
        "create", str(workdir / "out.zip"), ".", "--protect", "sercets/**",
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 2, result
    assert prompts == 0


@pytest.mark.usefixtures("tree")
@needs_pty
def test_no_password_is_asked_when_no_file_needs_it(workdir: Path) -> None:
    """The default rule decides nothing here, so its password is not needed."""
    result, prompts = terminal(
        "create", str(workdir / "out.zip"), ".",
        "--encryption", "aes256", "--protect", "**=none",
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 0
    assert set(schemes(workdir / "out.zip").values()) == {"none"}
    (workdir / "emptydir").mkdir()
    only_dirs, prompts = terminal(
        "create", str(workdir / "dirs.zip"), "emptydir", "--encryption", "aes256",
        cwd=workdir,
    )  # fmt: skip
    assert only_dirs.returncode == 0, only_dirs
    assert prompts == 0


@pytest.mark.usefixtures("tree")
@needs_pty
def test_no_password_is_asked_when_the_archive_already_exists(workdir: Path) -> None:
    (workdir / "out.zip").write_bytes(b"keep")
    result, prompts = terminal(
        "create",
        str(workdir / "out.zip"),
        ".",
        "--encryption",
        "aes256",
        cwd=workdir / "tree",
    )
    assert result.returncode == 1, result
    assert prompts == 0
    assert (workdir / "out.zip").read_bytes() == b"keep"


def test_an_equals_sign_inside_a_pattern_is_not_a_method(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "tree").mkdir()
    (workdir / "tree" / "k=v.txt").write_bytes(b"kv")
    (workdir / "tree" / "other.txt").write_bytes(b"o")
    result = create(
        cli, workdir, "--protect", "k=v.txt=none", "--encryption", "aes256", env=ENV
    )
    assert result.returncode == 0, result
    assert schemes(workdir / "out.zip") == {"k=v.txt": "none", "other.txt": "aes256"}


@pytest.mark.usefixtures("tree")
def test_the_member_names_that_rules_see_are_archive_paths(
    cli: CliRunner, workdir: Path
) -> None:
    result = cli(
        "create", str(workdir / "out.zip"), "tree", "--encryption", "aes256",
        "--protect", "tree/public/**=none",
        env=ENV, cwd=workdir,
    )  # fmt: skip
    assert result.returncode == 0, result
    assert schemes(workdir / "out.zip")["tree/public/readme.txt"] == "none"
    assert schemes(workdir / "out.zip")["tree/notes.txt"] == "aes256"


# --- --encryption-spec


def write_spec(workdir: Path, spec: str | JsonValue) -> str:
    path = workdir / "spec.json"
    path.write_text(spec if isinstance(spec, str) else json.dumps(spec))
    return str(path)


def spec_env(**extra: str) -> dict[str, str]:
    return {"DB_PASS": "db-secret", "DEFAULT_PASS": "default-secret", **extra}


FULL_SPEC: dict[str, JsonValue] = {
    "version": 1,
    "default": {"method": "aes256", "password": {"env": "DEFAULT_PASS"}},
    "rules": [
        {"match": "secrets/db.key", "method": "aes128", "password": {"env": "DB_PASS"}},
        {"match": "public/**", "method": "none"},
    ],
}


@pytest.mark.usefixtures("tree")
def test_a_spec_drives_per_file_encryption_with_no_typing(
    cli: CliRunner, workdir: Path
) -> None:
    spec = write_spec(workdir, FULL_SPEC)
    result = create(cli, workdir, "--encryption-spec", spec, env=spec_env())
    assert result.returncode == 0, result
    assert schemes(workdir / "out.zip") == {
        "public/readme.txt": "none",
        "public/logo.bin": "none",
        "secrets/db.key": "aes128",
        "secrets/api.key": "aes256",
        "notes.txt": "aes256",
    }
    assert matches(cli, workdir / "out.zip", "db-secret", "secrets/db.key")
    assert matches(
        cli, workdir / "out.zip", "default-secret", "notes.txt", "secrets/api.key"
    )
    assert not matches(cli, workdir / "out.zip", "db-secret", "notes.txt")
    assert "db-secret" not in result.stdout + result.stderr


@pytest.mark.usefixtures("tree")
def test_every_kind_of_password_reference(cli: CliRunner, workdir: Path) -> None:
    (workdir / "vault.pw").write_bytes(b"file-secret\n")
    spec = write_spec(
        workdir,
        {
            "rules": [
                {
                    "match": "secrets/db.key",
                    "method": "aes256",
                    "password": {"file": str(workdir / "vault.pw")},
                },
                {
                    "match": "secrets/api.key",
                    "method": "aes256",
                    "password": {"env": "API"},
                },
                {
                    "match": "notes.txt",
                    "method": "zipcrypto",
                    "password": {"stdin": True},
                },
            ]
        },
    )
    result = create(
        cli,
        workdir,
        "--encryption-spec",
        spec,
        env={"API": "api-secret"},
        stdin="stdin-secret\n",
    )
    assert result.returncode == 0, result
    archive = workdir / "out.zip"
    assert matches(cli, archive, "file-secret", "secrets/db.key")
    assert matches(cli, archive, "api-secret", "secrets/api.key")
    assert matches(cli, archive, "stdin-secret", "notes.txt")
    assert schemes(archive)["public/readme.txt"] == "none"


@pytest.mark.usefixtures("tree")
def test_a_spec_can_be_read_from_standard_input(cli: CliRunner, workdir: Path) -> None:
    result = create(
        cli,
        workdir,
        "--encryption-spec",
        "-",
        env=spec_env(),
        stdin=json.dumps(FULL_SPEC),
    )
    assert result.returncode == 0, result
    assert schemes(workdir / "out.zip")["notes.txt"] == "aes256"


@pytest.mark.usefixtures("tree")
def test_a_default_only_spec(cli: CliRunner, workdir: Path) -> None:
    spec = write_spec(
        workdir, {"default": {"method": "aes192", "password": {"env": "DEFAULT_PASS"}}}
    )
    assert (
        create(cli, workdir, "--encryption-spec", spec, env=spec_env()).returncode == 0
    )
    assert set(schemes(workdir / "out.zip").values()) == {"aes192"}


@pytest.mark.usefixtures("tree")
def test_a_spec_without_a_default_leaves_the_rest_plain(
    cli: CliRunner, workdir: Path
) -> None:
    spec = write_spec(
        workdir,
        {
            "rules": [
                {
                    "match": "secrets/**",
                    "method": "aes256",
                    "password": {"env": "DB_PASS"},
                }
            ]
        },
    )
    assert (
        create(cli, workdir, "--encryption-spec", spec, env=spec_env()).returncode == 0
    )
    assert schemes(workdir / "out.zip")["notes.txt"] == "none"
    assert schemes(workdir / "out.zip")["secrets/db.key"] == "aes256"


@pytest.mark.usefixtures("tree")
@needs_pty
def test_a_spec_can_ask_for_a_password_at_the_terminal(
    cli: CliRunner, workdir: Path
) -> None:
    spec = write_spec(
        workdir,
        {
            "rules": [
                {
                    "match": "secrets/**",
                    "method": "aes256",
                    "password": {"prompt": "Password for the vault"},
                }
            ]
        },
    )
    result, prompts = terminal(
        "create", str(workdir / "out.zip"), ".", "--encryption-spec", spec,
        replies=["vault", "vault"],
        cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 2
    assert "Password for the vault: " in result.stderr
    assert "Confirm password for the vault: " in result.stderr
    assert matches(cli, workdir / "out.zip", "vault", "secrets/db.key")


@pytest.mark.usefixtures("tree")
def test_a_prompt_in_a_spec_needs_a_terminal(cli: CliRunner, workdir: Path) -> None:
    spec = write_spec(
        workdir,
        {"default": {"method": "aes256", "password": {"prompt": "Password for all"}}},
    )
    result = create(cli, workdir, "--encryption-spec", spec)
    assert result.returncode == 2, result
    assert not (workdir / "out.zip").exists()


def one(**fields: JsonValue) -> str:
    """A spec with a single rule built from *fields*."""
    return json.dumps({"rules": [fields]})


ENV_X = {"env": "X"}
BAD_SPECS = [
    ("{not json", "not valid JSON"),
    ("[]", "expected a JSON object"),
    ('{"rulez": []}', "unknown key 'rulez' (did you mean 'rules'?)"),
    ('{"version": 2, "rules": []}', "version: unsupported"),
    ('{"rules": {}}', "rules: expected a list"),
    ('{"rules": []}', "defines no rules and no default"),
    ('{"rules": [1]}', "rules[0]: expected an object"),
    (one(method="aes256", password=ENV_X), "rules[0].match: required"),
    (one(match="a", password=ENV_X), "rules[0].method: required"),
    (one(match="a", method="rot13"), "rules[0].method: required: one of"),
    (one(match="a", method="aes256"), "rules[0].password: required"),
    (one(match="a", method="none", password=ENV_X), 'not allowed with method "none"'),
    (
        one(match="a", method="aes256", password={"value": "hunter2"}),
        "inline passwords are not allowed",
    ),
    (one(match="a", method="aes256", password="hunter2"), "expected an object"),
    (
        one(match="a", method="aes256", password={"env": "X", "file": "y"}),
        "expected exactly one of",
    ),
    (
        one(match="a", method="aes256", password={"env": "NOT_SET_ANYWHERE"}),
        "environment variable NOT_SET_ANYWHERE is not set",
    ),
    (
        one(match="a", method="aes256", password={"file": "/no/such/file"}),
        "cannot read password file",
    ),
    (one(match="a", method="aes256", password={"stdin": False}), "must be true"),
    (
        one(match="a", method="aes256", password={"prompt": ""}),
        "expected a non-empty string",
    ),
    (one(match="a", method="none", colour=1), "unknown key 'colour'"),
    ('{"default": {"match": "a", "method": "none"}}', "unknown key 'match'"),
    ('{"rules": [], "rules": []}', "duplicate key 'rules'"),
]


@pytest.mark.usefixtures("tree")
@pytest.mark.parametrize(("spec", "message"), BAD_SPECS)
def test_a_bad_spec_is_a_usage_error_and_writes_nothing(
    cli: CliRunner, workdir: Path, spec: str, message: str
) -> None:
    result = create(
        cli, workdir, "--encryption-spec", write_spec(workdir, spec), env=spec_env()
    )
    assert result.returncode == 2, result
    assert "invalid encryption spec" in result.stderr
    assert message in result.stderr
    assert "hunter2" not in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_all_the_problems_are_reported_together(cli: CliRunner, workdir: Path) -> None:
    spec = write_spec(
        workdir,
        {
            "rules": [
                {"match": "a", "method": "rot13"},
                {"match": "b", "method": "aes256"},
                {"match": "c", "method": "aes256", "password": {"value": "x"}},
            ]
        },
    )
    result = create(cli, workdir, "--encryption-spec", spec)
    assert result.returncode == 2
    detail = [line for line in result.stderr.splitlines() if line.startswith("  ")]
    assert len(detail) == 3


@pytest.mark.usefixtures("tree")
def test_duplicate_match_patterns_are_refused(cli: CliRunner, workdir: Path) -> None:
    rule = {"match": "a", "method": "none"}
    result = create(
        cli, workdir, "--encryption-spec", write_spec(workdir, {"rules": [rule, rule]})
    )
    assert result.returncode == 2
    assert "duplicate pattern 'a'" in result.stderr


@pytest.mark.usefixtures("tree")
def test_standard_input_serves_one_purpose_only(cli: CliRunner, workdir: Path) -> None:
    both: dict[str, JsonValue] = {
        "rules": [
            {"match": "a", "method": "aes256", "password": {"stdin": True}},
            {"match": "b", "method": "aes256", "password": {"stdin": True}},
        ]
    }
    result = create(
        cli, workdir, "--encryption-spec", write_spec(workdir, both), stdin="x\n"
    )
    assert result.returncode == 2
    assert "standard input can only be used by one password" in result.stderr
    spec_on_stdin = create(
        cli,
        workdir,
        "--encryption-spec",
        "-",
        stdin=json.dumps(
            {"default": {"method": "aes256", "password": {"stdin": True}}}
        ),
    )
    assert spec_on_stdin.returncode == 2
    assert "standard input cannot be used for both" in spec_on_stdin.stderr


@pytest.mark.usefixtures("tree")
def test_a_missing_spec_file(cli: CliRunner, workdir: Path) -> None:
    result = create(cli, workdir, "--encryption-spec", str(workdir / "nope.json"))
    assert result.returncode == 2
    assert "cannot read encryption spec" in result.stderr


@pytest.mark.usefixtures("tree")
@pytest.mark.parametrize(
    "extra",
    [
        ["--encryption", "aes256"],
        ["--protect", "a"],
        ["--password-stdin"],
        ["--password-prompt"],
    ],
)
def test_a_spec_cannot_be_mixed_with_the_other_ways_of_choosing(
    cli: CliRunner, workdir: Path, extra: list[str]
) -> None:
    spec = write_spec(workdir, FULL_SPEC)
    result = create(cli, workdir, "--encryption-spec", spec, *extra, env=spec_env())
    assert result.returncode == 2, result
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_a_spec_rule_that_decides_nothing_is_an_error(
    cli: CliRunner, workdir: Path
) -> None:
    spec = write_spec(
        workdir,
        {
            "rules": [
                {
                    "match": "nothing/**",
                    "method": "aes256",
                    "password": {"env": "DB_PASS"},
                }
            ]
        },
    )
    result = create(cli, workdir, "--encryption-spec", spec, env=spec_env())
    assert result.returncode == 2, result
    assert "no member is decided by the rule for 'nothing/**'" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_aes_version_applies_to_spec_rules(cli: CliRunner, workdir: Path) -> None:
    spec = write_spec(workdir, FULL_SPEC)
    create(
        cli, workdir, "--encryption-spec", spec, "--wz-aes-version", "1", env=spec_env()
    )
    listing = load_json(cli("list", "--json", str(workdir / "out.zip")), ListReport)
    crcs = {m["name"]: m["crc32"] for m in listing["members"]}
    assert crcs["notes.txt"] != "00000000"


# --- combined with the other options


@pytest.mark.usefixtures("tree")
def test_encryption_works_with_every_compression_method(
    cli: CliRunner, workdir: Path
) -> None:
    for method in ("store", "deflate", "bzip2", "lzma"):
        result = create(
            cli,
            workdir,
            "--encryption",
            "aes256",
            "--compression",
            method,
            "--force",
            env=ENV,
        )
        assert result.returncode == 0, (method, result)
        assert read_all(workdir / "out.zip", PW) == FILES


@pytest.mark.usefixtures("tree")
def test_append_can_add_encrypted_members_with_a_new_password(
    cli: CliRunner, workdir: Path
) -> None:
    assert (
        cli(
            "create", str(workdir / "out.zip"), "notes.txt", cwd=workdir / "tree"
        ).returncode
        == 0
    )
    result = cli(
        "create", str(workdir / "out.zip"), "secrets",
        "--append", "--encryption", "aes256",
        env=ENV, cwd=workdir / "tree",
    )  # fmt: skip
    assert result.returncode == 0, result
    assert result.stdout.startswith("Added ")
    found = schemes(workdir / "out.zip")
    assert found["notes.txt"] == "none"
    assert found["secrets/db.key"] == "aes256"
    assert matches(cli, workdir / "out.zip", PASSWORD)


@pytest.mark.usefixtures("tree")
def test_the_json_report_names_the_encryption(cli: CliRunner, workdir: Path) -> None:
    result = create(cli, workdir, "--encryption", "aes192", "--json", env=ENV)
    document = load_json(result, CreateReport)
    files = [m for m in document["members"] if not m["directory"]]
    assert {m["encryption"] for m in files} == {"AES-192"}
    assert PASSWORD not in result.stdout


@pytest.mark.usefixtures("tree")
def test_verbose_shows_the_encryption_of_each_member(
    cli: CliRunner, workdir: Path
) -> None:
    result = create(
        cli,
        workdir,
        "--encryption",
        "aes256",
        "--protect",
        "public/**=none",
        "-v",
        env=ENV,
    )
    assert "Adding: secrets/db.key (deflate, AES-256)" in result.stdout
    assert "Adding: public/logo.bin (deflate, none)" in result.stdout


def test_the_readme_spec_example_is_valid(workdir: Path) -> None:
    import io
    import re

    from zipctl.cli.commands.helpers.encryption_spec import plan_from_spec
    from zipctl.cli.commands.helpers.password_sources import readers_for
    from zipctl.cli.context import Context

    readme = Path(__file__).resolve().parents[3] / "README.md"
    blocks = [
        m[1]
        for m in re.finditer(r"```json\n(.*?)```", readme.read_text("utf-8"), re.DOTALL)
    ]
    (example,) = [b for b in blocks if '"match"' in b]
    vault = workdir / "vault"
    vault.write_bytes(b"secret\n")
    text = example.replace("/run/secrets/vault", str(vault).replace("\\", "\\\\"))
    ctx = Context(io.StringIO(), io.StringIO(), io.StringIO(), {"ZIPCTL_PASSWORD": "x"})
    plan = plan_from_spec(text, "README", readers_for(ctx))
    assert [(r.pattern, r.method.name) for r in plan.rules] == [
        ("secrets/**", "aes256"),
        ("*.key", "aes128"),
        ("public/**", "none"),
        (None, "aes256"),
    ]


# --- malformed patterns and method typos


@pytest.mark.usefixtures("tree")
def test_a_malformed_protect_pattern_is_a_usage_error(
    cli: CliRunner, workdir: Path
) -> None:
    result = create(cli, workdir, "--protect", "x**")
    assert result.returncode == 2, result
    assert "invalid pattern" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.usefixtures("tree")
def test_a_mistyped_protect_method_is_named(cli: CliRunner, workdir: Path) -> None:
    result = create(cli, workdir, "--protect", "notes.txt=aes265")
    assert result.returncode == 2, result
    assert "unknown method 'aes265' (did you mean 'aes256'?)" in result.stderr


@pytest.mark.usefixtures("tree")
def test_a_malformed_spec_pattern_is_reported_with_the_other_issues(
    cli: CliRunner, workdir: Path
) -> None:
    spec = write_spec(
        workdir,
        {
            "rules": [
                {"match": "[z-a]", "method": "none"},
                {"match": "ok", "method": "bogus"},
            ]
        },
    )
    result = create(cli, workdir, "--encryption-spec", spec)
    assert result.returncode == 2, result
    assert "rules[0].match: invalid pattern" in result.stderr
    assert "rules[1].method" in result.stderr
    assert "Traceback" not in result.stderr


# --- standard input and prompts without a terminal


@pytest.mark.usefixtures("tree")
def test_a_spec_on_standard_input_that_is_not_utf8_is_a_usage_error(
    cli: CliRunner, workdir: Path
) -> None:
    result = create(cli, workdir, "--encryption-spec", "-", stdin=b"\xff")
    assert result.returncode == 2, result
    assert "not valid UTF-8" in result.stderr
    assert "unexpected" not in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_the_protect_hint_names_the_pattern_once(cli: CliRunner, workdir: Path) -> None:
    result = create(cli, workdir, "--protect", "secrets/**", env=ENV)
    assert result.returncode == 2, result
    assert "the password for secrets/** can only be typed at a terminal" in (
        result.stderr
    )
    assert "Password for Password" not in result.stderr


@pytest.mark.usefixtures("tree")
@pytest.mark.parametrize(
    ("spec", "who"),
    [
        (
            {
                "rules": [
                    {
                        "match": "secrets/**",
                        "method": "aes256",
                        "password": {"prompt": "Vault key"},
                    }
                ]
            },
            "secrets/**",
        ),
        (
            {"default": {"method": "aes256", "password": {"prompt": "Vault key"}}},
            "the default rule",
        ),
    ],
)
def test_a_spec_prompt_without_a_terminal_points_at_the_spec_references(
    cli: CliRunner, workdir: Path, spec: dict[str, JsonValue], who: str
) -> None:
    result = create(cli, workdir, "--encryption-spec", "-", stdin=json.dumps(spec))
    assert result.returncode == 2, result
    assert f"the password for {who} can only be typed at a terminal" in result.stderr
    assert '"env"' in result.stderr
    assert "use --encryption-spec" not in result.stderr
