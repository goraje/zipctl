from __future__ import annotations

import io
import pathlib
import re

import pytest

import zipctl
from zipctl import Path, ZipFile
from zipctl.exceptions import BadPassword
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.path import CompleteDirs


def _make_archive(tmp_path: pathlib.Path) -> pathlib.Path:
    archive = tmp_path / "abcde.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", "content of a")
        zf.writestr("b/c.txt", "content of c")
        zf.writestr("b/d/e.txt", "content of e")
    return archive


class TestConstruction:
    def test_accepts_filename(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        # The archive root itself is not a named member (CPython parity):
        # exists() only reports on names present in the archive.
        assert not path.exists()
        assert path.is_dir()

    def test_accepts_open_zipfile_and_leaves_its_class_alone(
        self, tmp_path: pathlib.Path
    ) -> None:
        archive = _make_archive(tmp_path)
        zf = ZipFile(archive)
        path = Path(zf)
        assert type(zf) is ZipFile
        assert isinstance(path.root, CompleteDirs)
        assert path.root.zf is zf

    def test_wrapping_a_path_root_is_idempotent(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        zf = ZipFile(archive)
        inner = Path(zf)
        outer = Path(inner.root)
        assert outer.root is inner.root

    def test_writable_zipfile_does_not_get_fast_lookup(
        self, tmp_path: pathlib.Path
    ) -> None:
        archive = tmp_path / "writable.zip"
        zf = ZipFile(archive, "w")
        try:
            zf.writestr("a.txt", b"a")
            path = Path(zf)
            assert path.root.namelist() == ["a.txt"]
            zf.writestr("b.txt", b"b")
            assert path.root.namelist() == ["a.txt", "b.txt"]  # not cached
        finally:
            zf.close()


class TestNavigation:
    def test_iterdir_lists_root_children_only(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        children = {child.at for child in path.iterdir()}
        assert children == {"a.txt", "b/"}

    def test_iterdir_of_file_raises(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        with pytest.raises(ValueError, match="listdir a file"):
            next((path / "a.txt").iterdir())

    def test_truediv_and_joinpath_are_equivalent(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        assert (path / "b" / "c.txt") == path.joinpath("b", "c.txt")
        assert (path / "b/c.txt").at == "b/c.txt"

    def test_implied_directory_is_navigable(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        b = path / "b"
        assert b.is_dir()
        assert b.at == "b/"
        assert {child.name for child in b.iterdir()} == {"c.txt", "d"}

    def test_parent_of_nested_file(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        e = path / "b" / "d" / "e.txt"
        assert e.parent.at == "b/d/"
        assert e.parent.parent.at == "b/"

    def test_parent_at_root_returns_filesystem_parent(
        self, tmp_path: pathlib.Path
    ) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        assert path.parent == pathlib.Path(str(archive)).parent

    def test_relative_to(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        e = path / "b" / "d" / "e.txt"
        b = path / "b"
        assert e.relative_to(b) == "d/e.txt"


class TestNameProperties:
    def test_name_suffix_stem_of_file(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        c = path / "b" / "c.txt"
        assert c.name == "c.txt"
        assert c.suffix == ".txt"
        assert c.suffixes == [".txt"]
        assert c.stem == "c"

    def test_name_of_root_is_archive_name(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        assert path.name == archive.name

    def test_filename_property(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        c = path / "b" / "c.txt"
        assert c.filename == pathlib.Path(str(archive)) / "b" / "c.txt"

    def test_filename_without_archive_name_raises(self) -> None:
        zf = ZipFile(io.BytesIO(), "w")
        zf.writestr("a.txt", "content")
        zf.filename = None
        path = Path(zf)
        with pytest.raises(TypeError):
            _ = path.filename
        with pytest.raises(TypeError):
            _ = path.name
        with pytest.raises(TypeError):
            _ = path.parent


class TestExistenceAndType:
    def test_exists_true_and_false(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        assert (path / "a.txt").exists()
        assert not (path / "missing.txt").exists()

    def test_is_file_and_is_dir(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        assert (path / "a.txt").is_file()
        assert not (path / "a.txt").is_dir()
        assert (path / "b").is_dir()
        assert not (path / "b").is_file()
        assert path.is_dir()

    def test_is_symlink_false_for_regular_file(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        assert not (path / "a.txt").is_symlink()

    def test_is_symlink_true_for_symlink_entry(self, tmp_path: pathlib.Path) -> None:
        archive = tmp_path / "links.zip"
        with ZipFile(archive, "w") as zf:
            info = ZipInfo("link")
            info.external_attr = (0o120777 << 16) | 0xA000
            zf.writestr(info, "target")
        path = Path(archive)
        assert (path / "link").is_symlink()


class TestReading:
    def test_read_bytes(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        assert (path / "a.txt").read_bytes() == b"content of a"

    def test_read_text(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        assert (path / "b" / "c.txt").read_text(encoding="utf-8") == "content of c"

    def test_open_binary_rejects_text_args(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        with pytest.raises(ValueError, match="encoding args invalid"):
            (path / "a.txt").open("rb", "utf-8")  # type: ignore[call-overload]  # ty: ignore[invalid-argument-type]  # pyright: ignore[reportArgumentType]

    def test_open_missing_file_raises_file_not_found(
        self, tmp_path: pathlib.Path
    ) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        with pytest.raises(FileNotFoundError):
            (path / "missing.txt").open("r")

    def test_open_directory_raises_is_a_directory(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        with pytest.raises(IsADirectoryError):
            (path / "b").open("r")

    def test_open_with_password(self, tmp_path: pathlib.Path) -> None:
        archive = tmp_path / "encrypted.zip"
        password = b"correct-horse-battery-staple"
        with ZipFile(archive, "w", encryption=zipctl.ZIP_CRYPTO) as zf:
            zf.setpassword(password)
            zf.writestr("secret.txt", "top secret")

        path = Path(archive)
        with pytest.raises(RuntimeError, match="password"):
            (path / "secret.txt").read_bytes()
        assert (path / "secret.txt").open("rb", pwd=password).read() == b"top secret"

    def test_open_falls_back_to_archive_default_password(
        self, tmp_path: pathlib.Path
    ) -> None:
        archive = tmp_path / "encrypted-default.zip"
        password = b"another-secret"
        with ZipFile(archive, "w", encryption=zipctl.ZIP_CRYPTO) as zf:
            zf.setpassword(password)
            zf.writestr("secret.txt", "top secret")

        zf = ZipFile(archive)
        zf.setpassword(password)
        path = Path(zf)
        assert (path / "secret.txt").read_bytes() == b"top secret"


class TestMatchGlob:
    def test_match_uses_posix_pattern(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        c = path / "b" / "c.txt"
        assert c.match("*.txt")
        assert not c.match("*.bin")

    def test_glob_finds_direct_children(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        names = {p.at for p in path.glob("*.txt")}
        assert names == {"a.txt"}

    def test_rglob_finds_nested_matches(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        # rglob("*.txt") from the root requires at least one directory
        # segment before the match (CPython parity), so top-level "a.txt"
        # is excluded; use glob() for direct children.
        names = {p.at for p in path.rglob("*.txt")}
        assert names == {"b/c.txt", "b/d/e.txt"}

    def test_rglob_from_subdirectory_finds_nested_matches(
        self, tmp_path: pathlib.Path
    ) -> None:
        # Same quirk as at the root: rglob() requires at least one directory
        # segment below the starting point, so the direct child "b/c.txt" is
        # excluded and only the deeper "b/d/e.txt" matches.
        archive = _make_archive(tmp_path)
        path = Path(archive) / "b"
        names = {p.at for p in path.rglob("*.txt")}
        assert names == {"b/d/e.txt"}

    def test_glob_rejects_empty_pattern(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        with pytest.raises(ValueError, match="Unacceptable pattern"):
            list(path.glob(""))

    def test_glob_rejects_partial_double_star_segment(
        self, tmp_path: pathlib.Path
    ) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        with pytest.raises(ValueError, match=r"\*\* must appear alone"):
            list(path.glob("**foo"))


class TestStringingAndEquality:
    def test_str_and_repr(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        c = path / "b" / "c.txt"
        assert str(c) == f"{archive}/b/c.txt"
        assert repr(c) == f"Path({str(archive)!r}, 'b/c.txt')"

    def test_str_of_root_ends_with_separator(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        assert str(path) == f"{archive}/"

    def test_equality_and_hash(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        path = Path(archive)
        a1 = path / "a.txt"
        a2 = path / "a.txt"
        assert a1 == a2
        assert hash(a1) == hash(a2)
        assert a1 != "a.txt"

    def test_equality_requires_the_same_root_object(
        self, tmp_path: pathlib.Path
    ) -> None:
        # CPython parity: Path equality compares root identity/equality, so
        # two Path instances built from separate archive opens (even of the
        # same filename) are not equal.
        archive = _make_archive(tmp_path)
        assert Path(archive) / "a.txt" != Path(archive) / "a.txt"


class TestImpliedDirectories:
    def test_implied_dirs_are_deduplicated(self) -> None:
        names = [
            "foo/bar.txt",
            "foo/bar/baz.txt",
            "foo/bar/",
        ]
        assert list(CompleteDirs._implied_dirs(names)) == ["foo/"]

    def test_namelist_includes_implied_dirs(self, tmp_path: pathlib.Path) -> None:
        archive = _make_archive(tmp_path)
        with ZipFile(archive) as zf:
            wrapped = CompleteDirs.make(zf)
            names = wrapped.namelist()
        assert "b/" in names
        assert "b/d/" in names

    def test_inject_writes_directory_entries(self, tmp_path: pathlib.Path) -> None:
        archive = tmp_path / "inject.zip"
        with ZipFile(archive, "w") as zf:
            zf.writestr("b/c.txt", "content")
            CompleteDirs.inject(zf)
        with ZipFile(archive) as zf:
            assert "b/" in zf.namelist()


def test_read_aes_encrypted_member_through_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    # A wrong password passes the 2-byte verifier 1 in 65536 times with a
    # random salt; pin the salt so the rejection below is deterministic.

    def urandom(size: int) -> bytes:
        return bytes(size)

    monkeypatch.setattr("zipctl.cryptography.aes.os.urandom", urandom)
    archive = tmp_path / "secure.zip"
    password = b"hunter2-super-secret"
    with zipctl.ZipFile(archive, "w", encryption=zipctl.WZ_AES) as zf:
        zf.setpassword(password)
        zf.writestr("confidential/plan.txt", "launch codes")
        zf.writestr("public/notice.txt", "nothing to see here", encryption=None)

    root = Path(archive)

    # Unencrypted sibling member is readable without a password.
    assert (root / "public" / "notice.txt").read_bytes() == b"nothing to see here"

    # The encrypted member requires the password, matching ZipFile.open().
    encrypted_member = root / "confidential" / "plan.txt"
    with encrypted_member.open("rb", pwd=password) as fh:
        assert fh.read() == b"launch codes"

    # Passing the wrong password surfaces the same error ZipFile.open would.
    with pytest.raises(BadPassword):
        with encrypted_member.open("rb", pwd=b"wrong-password") as fh:
            fh.read()


def test_missing_path_is_not_a_symlink(tmp_path: pathlib.Path) -> None:
    archive = tmp_path / "missing.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("present.txt", b"payload")
    assert not (Path(archive) / "missing.txt").is_symlink()


@pytest.mark.parametrize(
    ("pattern", "name", "matches"),
    [("[a-c-e]", "-", True), ("[a-c-e]", "d", False), ("[a-c-e]", "e", True)],
)
def test_glob_sets_pair_ranges_like_re(pattern: str, name: str, matches: bool) -> None:
    from zipctl.zipfile.path.glob import Translator

    assert bool(re.fullmatch(Translator().translate(pattern), name)) is matches
