"""``ziplet rewrite``: change how an archive is protected or compressed."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typing_extensions import Unpack

import ziplet
from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.rewrite_support import (
    OTHER,
    OTHER_PW,
    PASSWORD,
    PW,
    leftovers,
    make_mixed,
    make_source,
    schemes,
    snapshot,
)
from tests.functional.cli.support import HAS_PTY, Result, RunOptions
from tests.functional.cli.support import run_in_terminal as terminal
from ziplet import ZipFile
from ziplet.compression import registry

OLD = {"ZIPLET_OLD_PASSWORD": PASSWORD}
NEW = {"ZIPLET_PASSWORD": OTHER}
BOTH = OLD | NEW
needs_pty = pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")
COMPRESSION = {
    "store": ziplet.ZIP_STORED,
    "deflate": ziplet.ZIP_DEFLATED,
    "bzip2": ziplet.ZIP_BZIP2,
    "lzma": ziplet.ZIP_LZMA,
}


@pytest.fixture
def secret(workdir: Path) -> Path:
    """The sample archive, AES-256, protected with PASSWORD."""
    return make_source(
        workdir / "in.zip",
        encryption=ziplet.WZ_AES,
        password=PW,
        extra=ziplet.ZipFileExtra(wz_aes_nbits=256),
    )


def rewrite(
    cli: CliRunner, workdir: Path, *args: str, **kw: Unpack[RunOptions]
) -> Result:
    return cli(
        "rewrite", str(workdir / "in.zip"), str(workdir / "out.zip"), *args, **kw
    )


def matches(cli: CliRunner, archive: Path, password: str) -> bool:
    result = cli(
        "check-password", "--full", str(archive), env={"ZIPLET_PASSWORD": password}
    )
    return result.returncode == 0


# --- doing nothing much -------------------------------------------------------


def test_without_options_it_is_a_faithful_copy(
    cli: CliRunner, workdir: Path, secret: Path
) -> None:
    result = rewrite(cli, workdir, env=OLD)
    assert result.returncode == 0, result
    out = workdir / "out.zip"
    assert snapshot(out, PW) == snapshot(secret, PW)
    assert schemes(out) == schemes(secret)
    assert matches(cli, out, PASSWORD)  # same password: nothing new was asked for


def test_a_plain_archive_is_copied_plain_without_any_password(
    cli: CliRunner, workdir: Path
) -> None:
    source = make_source(workdir / "in.zip")
    result = rewrite(cli, workdir)
    assert result.returncode == 0, result
    assert snapshot(workdir / "out.zip") == snapshot(source)
    assert set(schemes(workdir / "out.zip").values()) == {"none"}


# --- compression --------------------------------------------------------------


@pytest.mark.parametrize("method", list(COMPRESSION))
def test_recompress_changes_every_files_method_and_keeps_the_protection(
    cli: CliRunner, workdir: Path, secret: Path, method: str
) -> None:
    result = rewrite(cli, workdir, "--compression", method, env=OLD)
    assert result.returncode == 0, result
    out = workdir / "out.zip"
    after = snapshot(out, PW)
    before = snapshot(secret, PW)
    for name, row in after.items():
        assert row[5] == before[name][5], name
        if not row[4]:
            assert row[3] == COMPRESSION[method], name
    assert schemes(out) == schemes(secret)
    assert matches(cli, out, PASSWORD)


def test_recompress_level_changes_the_size(cli: CliRunner, workdir: Path) -> None:
    payload = bytes((i * 7) % 251 for i in range(4000)) * 30
    source = workdir / "in.zip"
    with ZipFile(source, "w", compression=ziplet.ZIP_DEFLATED) as zf:
        zf.writestr("data", payload)
    sizes = {}
    for level in ("1", "9"):
        out = workdir / f"out{level}.zip"
        result = cli(
            "rewrite", str(source), str(out), "--compression", "deflate", "-L", level
        )
        assert result.returncode == 0, result
        with ZipFile(out) as zf:
            sizes[level] = zf.getinfo("data").compress_size
            assert zf.read("data") == payload
    assert sizes["9"] < sizes["1"]


@pytest.mark.usefixtures("secret")
def test_a_level_needs_recompress(cli: CliRunner, workdir: Path) -> None:
    result = rewrite(cli, workdir, "-L", "9", env=OLD)
    assert result.returncode == 2, result
    assert "--compression" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("secret")
def test_a_bad_level_fails_cleanly(cli: CliRunner, workdir: Path) -> None:
    result = rewrite(cli, workdir, "--compression", "deflate", "-L", "99", env=OLD)
    assert result.returncode == 2, result
    assert "out of range for deflate" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


def zstd_installed() -> bool:
    try:
        registry.check_compression(ziplet.ZIP_ZSTANDARD)
    except (RuntimeError, NotImplementedError):
        return False
    return True


def test_zstd_works_where_it_is_installed_and_is_refused_elsewhere(
    cli: CliRunner, workdir: Path, secret: Path
) -> None:
    result = rewrite(cli, workdir, "--compression", "zstd", env=OLD)
    if zstd_installed():
        assert result.returncode == 0, result
        assert snapshot(workdir / "out.zip", PW) == {
            name: (*row[:3], ziplet.ZIP_ZSTANDARD, *row[4:]) if not row[4] else row
            for name, row in snapshot(secret, PW).items()
        }
    else:
        assert result.returncode == 2, result
        assert "not available" in result.stderr
        assert not (workdir / "out.zip").exists()


# --- changing the password / algorithm ----------------------------------------


def test_a_new_password_replaces_the_old_one(
    cli: CliRunner, workdir: Path, secret: Path
) -> None:
    result = rewrite(cli, workdir, "--encryption", "aes256", env=BOTH)
    assert result.returncode == 0, result
    out = workdir / "out.zip"
    assert matches(cli, out, OTHER)
    assert not matches(cli, out, PASSWORD)
    assert snapshot(out, OTHER_PW) == snapshot(secret, PW)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("aes256", "aes128"),
        ("aes128", "aes256"),
        ("aes192", "zipcrypto"),
        ("zipcrypto", "aes256"),
        ("zipcrypto", "aes192"),
    ],
)
def test_the_algorithm_can_be_changed(
    cli: CliRunner, workdir: Path, before: str, after: str
) -> None:
    if before == "zipcrypto":
        source = make_source(
            workdir / "in.zip", encryption=ziplet.ZIP_CRYPTO, password=PW
        )
    else:
        source = make_source(
            workdir / "in.zip",
            encryption=ziplet.WZ_AES,
            password=PW,
            extra=ziplet.ZipFileExtra(wz_aes_nbits=int(before[3:])),
        )
    result = rewrite(cli, workdir, "--encryption", after, env=BOTH)
    assert result.returncode == 0, result
    out = workdir / "out.zip"
    assert set(schemes(out).values()) == {after}
    assert snapshot(out, OTHER_PW) == snapshot(source, PW)


def test_the_aes_version_can_be_changed(cli: CliRunner, workdir: Path) -> None:
    make_source(
        workdir / "in.zip",
        encryption=ziplet.WZ_AES,
        password=PW,
        extra=ziplet.ZipFileExtra(wz_aes_nbits=256, force_wz_aes_version=1),
    )
    assert set(schemes(workdir / "in.zip").values()) == {"aes256-v1"}
    result = rewrite(
        cli, workdir, "--encryption", "aes256", "--wz-aes-version", "2", env=BOTH
    )
    assert result.returncode == 0, result
    assert set(schemes(workdir / "out.zip").values()) == {"aes256"}
    result = rewrite(
        cli,
        workdir,
        "--encryption",
        "aes256",
        "--wz-aes-version",
        "1",
        "--force",
        env=BOTH,
    )
    assert set(schemes(workdir / "out.zip").values()) == {"aes256-v1"}


def test_encrypt_none_removes_the_protection(
    cli: CliRunner, workdir: Path, secret: Path
) -> None:
    result = rewrite(cli, workdir, "--encryption", "none", env=OLD)
    assert result.returncode == 0, result
    assert set(schemes(workdir / "out.zip").values()) == {"none"}
    assert snapshot(workdir / "out.zip") == snapshot(secret, PW)


def test_a_plain_archive_can_be_protected_without_an_old_password(
    cli: CliRunner, workdir: Path
) -> None:
    source = make_source(workdir / "in.zip")
    result = rewrite(cli, workdir, "--encryption", "aes128", env=NEW)
    assert result.returncode == 0, result
    assert set(schemes(workdir / "out.zip").values()) == {"aes128"}
    assert snapshot(workdir / "out.zip", OTHER_PW) == snapshot(source)


@pytest.mark.usefixtures("secret")
def test_zipcrypto_warns(cli: CliRunner, workdir: Path) -> None:
    result = rewrite(cli, workdir, "--encryption", "zipcrypto", env=BOTH)
    assert "weak legacy cipher" in result.stderr
    quiet = rewrite(
        cli, workdir, "--encryption", "zipcrypto", "--force", "-q", env=BOTH
    )
    assert quiet.stderr == ""


def test_keeping_zipcrypto_does_not_warn(cli: CliRunner, workdir: Path) -> None:
    make_source(workdir / "in.zip", encryption=ziplet.ZIP_CRYPTO, password=PW)
    result = rewrite(cli, workdir, env=OLD)
    assert result.returncode == 0, result
    assert result.stderr == ""
    assert set(schemes(workdir / "out.zip").values()) == {"zipcrypto"}


# --- reading side -------------------------------------------------------------


@pytest.mark.usefixtures("secret")
def test_the_old_password_from_a_file(cli: CliRunner, workdir: Path) -> None:
    (workdir / "old").write_text(PASSWORD + "\n")
    result = rewrite(cli, workdir, "--old-password-file", str(workdir / "old"))
    assert result.returncode == 0, result


@pytest.mark.usefixtures("secret")
def test_the_old_password_from_standard_input(cli: CliRunner, workdir: Path) -> None:
    result = rewrite(cli, workdir, "--old-password-stdin", stdin=PASSWORD + "\n")
    assert result.returncode == 0, result


@pytest.mark.usefixtures("secret")
def test_the_old_password_and_the_new_one_from_different_sources(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "new").write_text(OTHER + "\n")
    result = rewrite(
        cli, workdir, "--old-password-stdin", "--password-file", str(workdir / "new"),
        "--encryption", "aes256", stdin=PASSWORD + "\n",
    )  # fmt: skip
    assert result.returncode == 0, result
    assert matches(cli, workdir / "out.zip", OTHER)


@pytest.mark.usefixtures("secret")
def test_both_passwords_cannot_come_from_standard_input(
    cli: CliRunner, workdir: Path
) -> None:
    result = rewrite(
        cli, workdir, "--old-password-stdin", "--password-stdin", "--encryption",
        "aes256", stdin=PASSWORD + "\n" + OTHER + "\n",
    )  # fmt: skip
    assert result.returncode == 2, result
    assert "standard input cannot be used for both" in result.stderr
    assert "the input password" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("secret")
def test_the_new_password_variable_is_not_the_old_password(
    cli: CliRunner, workdir: Path
) -> None:
    result = rewrite(cli, workdir, env={"ZIPLET_PASSWORD": PASSWORD})
    assert result.returncode == 1, result
    assert "password required" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("secret")
def test_a_wrong_old_password_writes_nothing(cli: CliRunner, workdir: Path) -> None:
    result = rewrite(
        cli,
        workdir,
        "--encryption",
        "aes256",
        env={**NEW, "ZIPLET_OLD_PASSWORD": "wrong"},
    )
    assert result.returncode == 1, result
    assert "wrong password" in result.stderr
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


@pytest.mark.usefixtures("secret")
def test_an_empty_old_password_on_standard_input_is_a_usage_error(
    cli: CliRunner, workdir: Path
) -> None:
    result = rewrite(cli, workdir, "--old-password-stdin", stdin="")
    assert result.returncode == 2, result
    assert "no password on standard input" in result.stderr


# --- option checks ------------------------------------------------------------


@pytest.mark.usefixtures("secret")
def test_password_options_need_an_encrypt(cli: CliRunner, workdir: Path) -> None:
    (workdir / "new").write_text(OTHER + "\n")
    result = rewrite(cli, workdir, "--password-file", str(workdir / "new"), env=OLD)
    assert result.returncode == 2, result
    assert "--encryption" in result.stderr


@pytest.mark.usefixtures("secret")
def test_an_aes_version_needs_aes(cli: CliRunner, workdir: Path) -> None:
    result = rewrite(cli, workdir, "--wz-aes-version", "1", env=OLD)
    assert result.returncode == 2, result
    result = rewrite(
        cli, workdir, "--encryption", "zipcrypto", "--wz-aes-version", "1", env=BOTH
    )
    assert result.returncode == 2, result


@pytest.mark.usefixtures("secret")
def test_the_spec_cannot_be_mixed_with_encrypt(cli: CliRunner, workdir: Path) -> None:
    (workdir / "spec.json").write_text('{"version": 1, "rules": []}')
    result = rewrite(
        cli, workdir, "--encryption-spec", str(workdir / "spec.json"), "--encryption",
        "aes256", env=BOTH,
    )  # fmt: skip
    assert result.returncode == 2, result
    assert "cannot be combined" in result.stderr


# --- per-file rules -----------------------------------------------------------


@pytest.mark.usefixtures("secret")
def test_protect_without_a_terminal_points_at_the_spec(
    cli: CliRunner, workdir: Path
) -> None:
    result = rewrite(cli, workdir, "--protect", "docs/**", env=OLD)
    assert result.returncode == 2, result
    assert "--encryption-spec" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("secret")
def test_a_protect_rule_that_decides_nothing_is_an_error_before_any_password(
    cli: CliRunner, workdir: Path
) -> None:
    result = rewrite(cli, workdir, "--protect", "typo/**")
    assert result.returncode == 2, result
    assert "typo/**" in result.stderr
    assert "password required" not in result.stderr


def write_spec(workdir: Path, rules: list[dict[str, object]], **top: object) -> Path:
    spec = workdir / "spec.json"
    spec.write_text(json.dumps({"version": 1, "rules": rules, **top}))
    return spec


def test_a_spec_protects_groups_with_their_own_passwords_and_keeps_the_rest(
    cli: CliRunner, workdir: Path, secret: Path
) -> None:
    (workdir / "docs.pw").write_text(OTHER + "\n")
    spec = write_spec(
        workdir,
        [
            {"match": "docs/**", "method": "aes128",
             "password": {"file": str(workdir / "docs.pw")}},
            {"match": "run.sh", "method": "none"},
        ],
    )  # fmt: skip
    result = rewrite(cli, workdir, "--encryption-spec", str(spec), env=OLD)
    assert result.returncode == 0, result
    out = workdir / "out.zip"
    got = schemes(out)
    assert got["docs/readme.txt"] == got["docs/data.bin"] == "aes128"
    assert got["run.sh"] == "none"
    assert {got["empty.txt"], got["link"], got["notes/ünïcode ✓.txt"]} == {"aes256"}
    passwords = {name: OTHER_PW if name.startswith("docs/") else PW for name in got}
    assert snapshot(out, passwords) == snapshot(secret, PW)


@pytest.mark.usefixtures("secret")
def test_a_spec_default_of_none_decrypts_everything_else(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "docs.pw").write_text(OTHER + "\n")
    spec = write_spec(
        workdir,
        [{"match": "docs/**", "method": "aes256",
          "password": {"file": str(workdir / "docs.pw")}}],
        default={"method": "none"},
    )  # fmt: skip
    result = rewrite(cli, workdir, "--encryption-spec", str(spec), env=OLD)
    assert result.returncode == 0, result
    got = schemes(workdir / "out.zip")
    assert {v for k, v in got.items() if not k.startswith("docs/")} == {"none"}


@pytest.mark.usefixtures("secret")
def test_a_spec_rule_that_decides_nothing_is_an_error(
    cli: CliRunner, workdir: Path
) -> None:
    spec = write_spec(workdir, [{"match": "typo/**", "method": "none"}])
    result = rewrite(cli, workdir, "--encryption-spec", str(spec), env=OLD)
    assert result.returncode == 2, result
    assert "typo/**" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("secret")
def test_an_invalid_spec_is_a_usage_error(cli: CliRunner, workdir: Path) -> None:
    (workdir / "spec.json").write_text("{not json")
    result = rewrite(
        cli, workdir, "--encryption-spec", str(workdir / "spec.json"), env=OLD
    )
    assert result.returncode == 2, result
    assert not (workdir / "out.zip").exists()


@needs_pty
def test_protect_asks_for_the_rules_password_twice(workdir: Path, secret: Path) -> None:
    result, prompts = terminal(
        "rewrite", str(workdir / "in.zip"), str(workdir / "out.zip"),
        "--old-password-file", str(_file(workdir, "old", PASSWORD)),
        "--protect", "docs/**=aes128",
        replies=["docs secret", "docs secret"],
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 2
    got = schemes(workdir / "out.zip")
    assert got["docs/readme.txt"] == "aes128"
    assert got["run.sh"] == "aes256"
    passwords = {n: (b"docs secret" if n.startswith("docs/") else PW) for n in got}
    assert snapshot(workdir / "out.zip", passwords) == snapshot(secret, PW)


def _file(workdir: Path, name: str, text: str) -> Path:
    path = workdir / name
    path.write_text(text + "\n")
    return path


@pytest.mark.usefixtures("secret")
@needs_pty
def test_the_old_password_cannot_be_typed_into_a_stdin_option(workdir: Path) -> None:
    result, prompts = terminal(
        "rewrite", str(workdir / "in.zip"), str(workdir / "out.zip"),
        "--old-password-stdin",
    )  # fmt: skip
    assert result.returncode == 2, result
    assert prompts == 0
    assert "--old-password-stdin expects the password piped" in result.stderr
    assert "--password-prompt" not in result.stderr  # not an option of the old side


@pytest.mark.usefixtures("secret")
@needs_pty
def test_old_passwords_are_prompted_before_new_ones(workdir: Path) -> None:
    result, prompts = terminal(
        "rewrite", str(workdir / "in.zip"), str(workdir / "out.zip"),
        "--encryption", "aes256",
        replies=[PASSWORD, OTHER, OTHER],
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 3
    first = result.stderr.index("Password for docs/readme.txt")
    assert first < result.stderr.index("Confirm password")


@needs_pty
def test_an_archive_with_two_passwords_is_read_with_two_prompts(
    workdir: Path,
) -> None:
    make_mixed(workdir / "in.zip")
    result, prompts = terminal(
        "rewrite", str(workdir / "in.zip"), str(workdir / "out.zip"),
        "--compression", "store", replies=[PASSWORD, OTHER],
    )  # fmt: skip
    assert result.returncode == 0, result
    assert prompts == 2
    assert schemes(workdir / "out.zip") == schemes(workdir / "in.zip")
    passwords = {"a.txt": PW, "b.txt": OTHER_PW, "d.txt": PW}
    after = snapshot(workdir / "out.zip", passwords)
    before = snapshot(workdir / "in.zip", passwords)
    assert {n: row[5] for n, row in after.items()} == {
        n: row[5] for n, row in before.items()
    }
    assert {row[3] for row in after.values()} == {ziplet.ZIP_STORED}


@pytest.mark.usefixtures("secret")
@needs_pty
def test_interrupting_leaves_nothing(workdir: Path) -> None:
    result, _ = terminal(
        "rewrite",
        str(workdir / "in.zip"),
        str(workdir / "out.zip"),
        interrupt_at_prompt=1,
    )
    assert result.returncode == 130, result
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


@pytest.mark.usefixtures("secret")
@needs_pty
@pytest.mark.skipif(sys.version_info < (3, 14), reason="masking needs Python 3.14")
def test_the_old_password_prompt_is_masked_on_3_14(workdir: Path) -> None:
    result, _ = terminal(
        "rewrite", str(workdir / "in.zip"), str(workdir / "out.zip"), replies=[PASSWORD]
    )
    assert result.returncode == 0, result
    assert "*" * len(PASSWORD) in result.stderr


# --- reporting ----------------------------------------------------------------


@pytest.mark.usefixtures("secret")
def test_verbose_shows_what_changed_per_member(cli: CliRunner, workdir: Path) -> None:
    result = rewrite(cli, workdir, "--encryption", "aes128", "-v", env=BOTH)
    assert "run.sh (store, AES-256 -> AES-128)" in result.stdout
    kept = rewrite(cli, workdir, "--force", "-v", env=OLD)
    assert "run.sh (store, AES-256)" in kept.stdout
