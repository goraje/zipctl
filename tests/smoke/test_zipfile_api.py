"""Smoke tests â€” ZipFile API surface not covered by the round-trip matrix."""

from __future__ import annotations

import io
import warnings
from pathlib import Path

import pytest

import zipctl
from zipctl import WzAesExtra, ZipFile, ZipFileExtra, is_zipfile
from zipctl.exceptions import BadZipFile

PASSWORD = b"ruhsuc-6wazmI-xicbib"
CONTENT = b"smoke test payload"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_zip(buf: io.BytesIO, entries: dict[str, bytes]) -> io.BytesIO:
    """Write a plain (unencrypted) ZIP into *buf* and rewind it."""
    with ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# 1. is_zipfile
# ---------------------------------------------------------------------------


class TestIsZipfile:
    def test_valid_zip_path(self, tmp_path: Path) -> None:
        path = tmp_path / "ok.zip"
        with ZipFile(path, "w") as zf:
            zf.writestr("f.txt", "hi")
        assert is_zipfile(path) is True

    def test_non_zip_path_returns_false(self, tmp_path: Path) -> None:
        path = tmp_path / "notazip.bin"
        path.write_bytes(b"this is not a zip file at all")
        assert is_zipfile(path) is False

    def test_valid_zip_bytesio(self) -> None:
        buf = _write_zip(io.BytesIO(), {"f.txt": b"data"})
        assert is_zipfile(buf) is True

    def test_bytesio_position_restored_after_check(self) -> None:
        buf = _write_zip(io.BytesIO(), {"f.txt": b"data"})
        buf.seek(4)
        is_zipfile(buf)
        assert buf.tell() == 4

    def test_empty_bytesio_returns_false(self) -> None:
        assert is_zipfile(io.BytesIO()) is False


# ---------------------------------------------------------------------------
# 2. In-memory ZipFile (BytesIO)
# ---------------------------------------------------------------------------


class TestInMemoryZipFile:
    def test_write_and_read_from_bytesio(self) -> None:
        buf = io.BytesIO()
        with ZipFile(buf, "w") as zf:
            zf.writestr("hello.txt", "world")
        buf.seek(0)
        with ZipFile(buf, "r") as zf:
            assert zf.read("hello.txt") == b"world"

    def test_encrypted_round_trip_in_memory(self) -> None:
        buf = io.BytesIO()
        with ZipFile(buf, "w", encryption=zipctl.WZ_AES) as zf:
            zf.setpassword(PASSWORD)
            zf.writestr("f.txt", CONTENT)
        buf.seek(0)
        with ZipFile(buf, "r") as zf:
            zf.setpassword(PASSWORD)
            assert zf.read("f.txt") == CONTENT


# ---------------------------------------------------------------------------
# 3. Bad archive / mode errors
# ---------------------------------------------------------------------------


class TestBadArchiveErrors:
    def test_open_non_zip_raises_bad_zip_file(self, tmp_path: Path) -> None:
        path = tmp_path / "garbage.zip"
        path.write_bytes(b"PK garbage not a real zip")
        with pytest.raises(BadZipFile):
            ZipFile(path, "r")

    def test_exclusive_mode_on_existing_file_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "existing.zip"
        path.write_bytes(b"")
        with pytest.raises(FileExistsError):
            ZipFile(path, "x")

    def test_invalid_mode_raises_value_error(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="mode"):
            ZipFile(tmp_path / "x.zip", "q")  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]  # pyright: ignore[reportArgumentType]

    def test_metadata_encoding_on_write_raises_value_error(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ValueError, match="metadata_encoding"):
            ZipFile(tmp_path / "x.zip", "w", metadata_encoding="cp437")


# ---------------------------------------------------------------------------
# 5. Archive comment
# ---------------------------------------------------------------------------


class TestArchiveComment:
    def test_comment_round_trip(self, tmp_path: Path) -> None:
        path = tmp_path / "commented.zip"
        with ZipFile(path, "w") as zf:
            zf.writestr("f.txt", "data")
            zf.comment = b"hello archive"
        with ZipFile(path, "r") as zf:
            assert zf.comment == b"hello archive"

    def test_comment_non_bytes_raises_type_error(self, tmp_path: Path) -> None:
        path = tmp_path / "c.zip"
        with ZipFile(path, "w") as zf:
            with pytest.raises(TypeError):
                zf.comment = "not bytes"  # type: ignore[assignment]  # ty: ignore[invalid-assignment]  # pyright: ignore[reportAttributeAccessIssue]

    def test_oversized_comment_is_truncated(self, tmp_path: Path) -> None:
        path = tmp_path / "c.zip"
        big_comment = b"x" * (0xFFFF + 10)
        with ZipFile(path, "w") as zf:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                zf.comment = big_comment
            assert any("truncating" in str(w.message).lower() for w in caught)
            assert len(zf.comment) == 0xFFFF


# ---------------------------------------------------------------------------
# 6. namelist / infolist / getinfo
# ---------------------------------------------------------------------------


class TestDirectoryLookup:
    def _make_multi(self, tmp_path: Path) -> Path:
        path = tmp_path / "multi.zip"
        with ZipFile(path, "w") as zf:
            zf.writestr("a.txt", b"aaa")
            zf.writestr("b.txt", b"bbb")
            zf.writestr("c.txt", b"ccc")
        return path

    def test_namelist_returns_all_names(self, tmp_path: Path) -> None:
        path = self._make_multi(tmp_path)
        with ZipFile(path, "r") as zf:
            assert zf.namelist() == ["a.txt", "b.txt", "c.txt"]

    def test_infolist_returns_zipinfo_objects(self, tmp_path: Path) -> None:
        path = self._make_multi(tmp_path)
        with ZipFile(path, "r") as zf:
            infos = zf.infolist()
            assert [(i.filename, i.file_size) for i in infos] == [
                ("a.txt", 3),
                ("b.txt", 3),
                ("c.txt", 3),
            ]
            assert [zf.read(i) for i in infos] == [b"aaa", b"bbb", b"ccc"]

    def test_getinfo_returns_correct_entry(self, tmp_path: Path) -> None:
        path = self._make_multi(tmp_path)
        with ZipFile(path, "r") as zf:
            info = zf.getinfo("b.txt")
            assert info is zf.infolist()[1]
            assert zf.read(info) == b"bbb"

    def test_getinfo_missing_raises_key_error(self, tmp_path: Path) -> None:
        path = self._make_multi(tmp_path)
        with ZipFile(path, "r") as zf:
            with pytest.raises(KeyError):
                zf.getinfo("nonexistent.txt")


# ---------------------------------------------------------------------------
# 7. Append mode
# ---------------------------------------------------------------------------


class TestAppendMode:
    def test_append_preserves_existing_entries(self, tmp_path: Path) -> None:
        path = tmp_path / "app.zip"
        with ZipFile(path, "w") as zf:
            zf.writestr("original.txt", b"original")
        with ZipFile(path, "a") as zf:
            zf.writestr("added.txt", b"added")
        with ZipFile(path, "r") as zf:
            assert set(zf.namelist()) == {"original.txt", "added.txt"}
            assert zf.read("original.txt") == b"original"
            assert zf.read("added.txt") == b"added"

    def test_append_to_non_zip_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "nozip.zip"
        path.write_bytes(b"not a zip")
        with pytest.raises(BadZipFile):
            ZipFile(path, "a")
        assert path.read_bytes() == b"not a zip"

    def test_append_to_empty_or_missing_file_starts_an_archive(
        self, tmp_path: Path
    ) -> None:
        empty = tmp_path / "empty.zip"
        empty.touch()
        for path in (empty, tmp_path / "missing.zip"):
            with ZipFile(path, "a") as zf:
                zf.writestr("new.txt", b"new")
            with ZipFile(path) as zf:
                assert zf.namelist() == ["new.txt"]

    def test_append_never_orphans_members_of_a_damaged_archive(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "counts.zip"
        with ZipFile(path, "w") as zf:
            zf.writestr("old.txt", b"old")
        data = bytearray(path.read_bytes())
        end = data.rfind(b"PK\x05\x06")
        data[end + 8 : end + 10] = (3).to_bytes(2, "little")  # this disk's count
        path.write_bytes(bytes(data))
        with pytest.raises(BadZipFile, match="entry counts differ"):
            ZipFile(path, "a")
        assert path.read_bytes() == bytes(data)

    def test_writestr_with_an_existing_info_leaves_it_untouched(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "a.zip"
        with ZipFile(path, "w") as zf:
            zf.writestr("a.txt", b"one")
        with ZipFile(path, "a") as zf:
            info = zf.getinfo("a.txt")
            before = (info.header_offset, info.CRC, info.file_size)
            with pytest.raises(ValueError, match="Duplicate name"):
                zf.writestr(info, b"twenty-two")
            assert (info.header_offset, info.CRC, info.file_size) == before
        with ZipFile(path) as zf:
            assert zf.read("a.txt") == b"one"


# ---------------------------------------------------------------------------
# 8. testzip
# ---------------------------------------------------------------------------


class TestTestZip:
    def test_testzip_intact_archive_returns_none(self, tmp_path: Path) -> None:
        path = tmp_path / "ok.zip"
        with ZipFile(path, "w") as zf:
            zf.writestr("f.txt", b"data")
        with ZipFile(path, "r") as zf:
            assert zf.testzip() is None

    def test_testzip_names_first_corrupt_member(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.zip"
        with ZipFile(path, "w") as zf:
            zf.writestr("good.txt", b"good data")
            zf.writestr("bad.txt", b"bad data")
        raw = bytearray(path.read_bytes())
        raw[raw.index(b"bad data")] ^= 0xFF
        path.write_bytes(raw)
        with ZipFile(path, "r") as zf:
            assert zf.testzip() == "bad.txt"


# ---------------------------------------------------------------------------
# 9. ZipFileExtra â€” nbits and force_wz_aes_version
# ---------------------------------------------------------------------------


class TestZipFileExtra:
    @pytest.mark.parametrize(
        ("nbits", "expected_strength"), [(128, 1), (192, 2), (256, 3)]
    )
    def test_wz_aes_nbits_sets_strength(
        self, tmp_path: Path, nbits: int, expected_strength: int
    ) -> None:
        path = tmp_path / "nbits.zip"
        x = ZipFileExtra(wz_aes_nbits=nbits)
        with ZipFile(path, "w", encryption=zipctl.WZ_AES, extra=x) as zf:
            zf.setpassword(PASSWORD)
            zf.writestr("f.txt", CONTENT)
        with ZipFile(path, "r") as zf:
            zf.setpassword(PASSWORD)
            info = zf.getinfo("f.txt")
            assert info.aes_extra == WzAesExtra(2, b"AE", expected_strength)
            assert zf.read("f.txt") == CONTENT


# ---------------------------------------------------------------------------
# 10. setpassword type checking
# ---------------------------------------------------------------------------


class TestSetPassword:
    def test_non_bytes_password_raises_type_error(self, tmp_path: Path) -> None:
        path = tmp_path / "x.zip"
        with ZipFile(path, "w") as zf:
            with pytest.raises(TypeError, match="bytes"):
                zf.setpassword("not bytes")  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]  # pyright: ignore[reportArgumentType]

    def test_none_clears_password(self, tmp_path: Path) -> None:
        path = tmp_path / "x.zip"
        with ZipFile(path, "w") as zf:
            zf.setpassword(PASSWORD)
            zf.setpassword(None)
            assert zf.pwd is None
