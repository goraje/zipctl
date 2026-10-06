from __future__ import annotations

import io
import stat
import struct
import zlib
from pathlib import Path

import pytest

import zipctl
from zipctl.cryptography import (
    WZ_AES,
    WZ_AES_V1,
    WZ_AES_V2,
    ZIP_CRYPTO,
    wz_aes_stores_crc,
)
from zipctl.exceptions import BadZipFile
from zipctl.zipfile.info import WzAesExtra, ZipInfo
from zipctl.zipfile.info.extra import iter_extra, strip_extra
from zipctl.zipfile.records import data_descriptor
from zipctl.zipfile.records.extra import decode_extra
from zipctl.zipfile.shared import (
    MASK_ENCRYPTED,
    MASK_USE_DATA_DESCRIPTOR,
    MASK_UTF_FILENAME,
    sanitize_filename,
)

# ---------------------------------------------------------------------------
# sanitize_filename
# ---------------------------------------------------------------------------


class TestSanitizeFilename:
    def test_plain_filename_unchanged(self) -> None:
        assert sanitize_filename("hello.txt") == "hello.txt"

    def test_null_byte_truncates(self) -> None:
        assert sanitize_filename("file\x00.txt") == "file"

    def test_null_byte_at_start_gives_empty(self) -> None:
        assert sanitize_filename("\x00rest") == ""

    def test_forward_slash_path_unchanged(self) -> None:
        assert sanitize_filename("a/b/c.txt") == "a/b/c.txt"


# ---------------------------------------------------------------------------
# Extra
# ---------------------------------------------------------------------------


def _make_extra_field(tag: int, body: bytes) -> bytes:
    return struct.pack("<HH", tag, len(body)) + body


class TestExtra:
    def test_iter_extra_yields_tag_and_body(self) -> None:
        data = _make_extra_field(0x0001, b"\x01" * 8) + _make_extra_field(
            0x9901, b"\x02" * 7
        )
        assert list(iter_extra(data)) == [(0x0001, b"\x01" * 8), (0x9901, b"\x02" * 7)]

    def test_iter_extra_empty_yields_nothing(self) -> None:
        assert list(iter_extra(b"")) == []

    @pytest.mark.parametrize("padding", [b"\x00", b"\x00" * 2, b"\x01" * 3])
    def test_iter_extra_skips_trailing_padding(self, padding: bytes) -> None:
        # Too short for a field header; zipalign writes these, 7-Zip skips them.
        field = struct.pack("<HH", 0xBEEF, 1) + b"\x02"
        assert list(iter_extra(field + padding)) == [(0xBEEF, b"\x02")]
        assert list(iter_extra(padding)) == []

    def test_iter_extra_rejects_overrun(self) -> None:
        with pytest.raises(BadZipFile, match="size=9"):
            list(iter_extra(struct.pack("<HH", 0xBEEF, 9) + b"\x00" * 8))

    def test_strip_removes_matching_tag(self) -> None:
        f1 = _make_extra_field(0x0001, b"\x00" * 8)
        f2 = _make_extra_field(0x9901, b"\x00" * 7)
        assert strip_extra(f1 + f2, {0x0001}) == f2

    def test_strip_keeps_unmatched_fields(self) -> None:
        f1 = _make_extra_field(0x0001, b"\x00" * 8)
        f2 = _make_extra_field(0x9901, b"\x00" * 7)
        assert strip_extra(f1 + f2, {0xDEAD}) == f1 + f2

    def test_strip_empty_input(self) -> None:
        assert strip_extra(b"", {0x0001}) == b""


# ---------------------------------------------------------------------------
# ZipInfo
# ---------------------------------------------------------------------------


class TestZipInfoInit:
    def test_default_filename(self) -> None:
        zi = ZipInfo()
        assert zi.filename == "NoName"

    def test_date_before_1980_raises(self) -> None:
        with pytest.raises(ValueError, match="1980"):
            ZipInfo(date_time=(1979, 1, 1, 0, 0, 0))

    def test_date_exactly_1980_is_valid(self) -> None:
        zi = ZipInfo(date_time=(1980, 1, 1, 0, 0, 0))
        assert zi.date_time[0] == 1980


class TestZipInfoProperties:
    def test_is_encrypted_true_when_flag_set(self) -> None:
        zi = ZipInfo()
        zi.flag_bits = MASK_ENCRYPTED
        assert zi.is_encrypted

    def test_is_utf_filename_true_when_flag_set(self) -> None:
        zi = ZipInfo()
        zi.flag_bits = MASK_UTF_FILENAME
        assert zi.is_utf_filename

    def test_use_data_descriptor_follows_flag(self) -> None:
        zi = ZipInfo()
        assert not zi.use_data_descriptor
        zi.flag_bits = MASK_USE_DATA_DESCRIPTOR
        assert zi.use_data_descriptor


class TestZipInfoDosDateTime:
    def test_get_dosdate_epoch(self) -> None:
        zi = ZipInfo(date_time=(1980, 1, 1, 0, 0, 0))
        assert zi.get_dosdate() == (0 << 9 | 1 << 5 | 1)

    def test_get_dosdate_known_value(self) -> None:
        # 2024-06-15 â†’ (2024-1980)<<9 | 6<<5 | 15 = 44<<9 | 192 | 15
        zi = ZipInfo(date_time=(2024, 6, 15, 0, 0, 0))
        assert zi.get_dosdate() == (44 << 9) | (6 << 5) | 15

    def test_get_dostime_midnight(self) -> None:
        zi = ZipInfo(date_time=(1980, 1, 1, 0, 0, 0))
        assert zi.get_dostime() == 0

    def test_get_dostime_known_value(self) -> None:
        # 13:30:44 â†’ 13<<11 | 30<<5 | 22 (44//2)
        zi = ZipInfo(date_time=(1980, 1, 1, 13, 30, 44))
        assert zi.get_dostime() == (13 << 11) | (30 << 5) | 22

    def test_get_dostime_odd_second_truncated(self) -> None:
        zi_even = ZipInfo(date_time=(1980, 1, 1, 0, 0, 4))
        zi_odd = ZipInfo(date_time=(1980, 1, 1, 0, 0, 5))
        assert zi_even.get_dostime() == zi_odd.get_dostime()


class TestDataDescriptor:
    def test_non_zip64_format(self) -> None:
        zi = ZipInfo()
        zi.CRC, zi.compress_size, zi.file_size = 0xDEADBEEF, 100, 200
        result = data_descriptor(zi, False)
        sig, crc, csz, fsz = struct.unpack("<LLLL", result)
        assert sig == 0x08074B50
        assert crc == 0xDEADBEEF
        assert csz == 100
        assert fsz == 200

    def test_zip64_format_uses_q_fields(self) -> None:
        zi = ZipInfo()
        zi.CRC, zi.compress_size, zi.file_size = 0, 2**32, 2**33
        result = data_descriptor(zi, True)
        sig, _, csz, fsz = struct.unpack("<LLQQ", result)
        assert sig == 0x08074B50
        assert csz == 2**32
        assert fsz == 2**33


class TestZipInfoDecodeExtraWzAes:
    def _make_wz_aes_extra(
        self, version: int = 1, strength: int = 3, compress_type: int = 8
    ) -> bytes:
        # tag(H) + size(H) + version(H) + vendor_id(2s) + strength(B) + compress_type(H)
        body = struct.pack("<H2sBH", version, b"AE", strength, compress_type)
        return struct.pack("<HH", 0x9901, len(body)) + body

    def test_valid_field_populates_aes_extra(self) -> None:
        zi = ZipInfo()
        raw = self._make_wz_aes_extra(version=1, strength=3, compress_type=8)
        zi.extra = raw
        decode_extra(zi, 0)
        assert zi.aes_extra == WzAesExtra(1, b"AE", 3)
        assert zi.compress_type == 8

    def test_invalid_length_raises_bad_zip_file(self) -> None:
        zi = ZipInfo()
        body = b"\x00" * 5  # wrong length (must be 7)
        raw = struct.pack("<HH", 0x9901, 5) + body
        zi.extra = raw
        with pytest.raises(BadZipFile):
            decode_extra(zi, 0)

    @pytest.mark.parametrize(
        ("fields", "message"),
        [
            ({"version": 3}, "Unsupported WinZip AES version"),
            ({"strength": 4}, "Invalid WinZip AES strength"),
            ({"strength": 0}, "Invalid WinZip AES strength"),
        ],
    )
    def test_out_of_range_fields_are_refused(
        self, fields: dict[str, int], message: str
    ) -> None:
        zi = ZipInfo()
        zi.extra = self._make_wz_aes_extra(**fields)
        with pytest.raises(BadZipFile, match=message):
            decode_extra(zi, 0)

    def test_a_wrong_vendor_id_is_refused(self) -> None:
        zi = ZipInfo()
        body = struct.pack("<H2sBH", 2, b"XX", 3, 8)
        zi.extra = struct.pack("<HH", 0x9901, len(body)) + body
        with pytest.raises(BadZipFile, match="Invalid WinZip AES vendor ID"):
            decode_extra(zi, 0)

    def test_unknown_extra_tag_silently_ignored(self) -> None:
        zi = ZipInfo()
        zi.extra = struct.pack("<HH", 0xBEEF, 4) + b"\x00" * 4
        decode_extra(zi, 0)
        assert zi.aes_extra is None
        assert zi.compress_type == ZipInfo().compress_type


class TestCarriedExtra:
    @staticmethod
    def _field(tag: int, body: bytes = b"\x00\x00") -> bytes:
        return struct.pack("<HH", tag, len(body)) + body

    def test_keeps_timestamps_and_drops_what_the_writer_builds_again(self) -> None:
        timestamp = self._field(0x5455, b"\x01\x02\x03\x04\x05")
        zi = ZipInfo()
        zi.extra = (
            self._field(0x0001, b"\x00" * 8)  # ZIP64
            + timestamp
            + self._field(0x9901, b"\x00" * 7)  # WinZip AES
            + self._field(0x7075, b"\x01" + b"\x00" * 4)  # Unicode path
        )
        assert zi.carried_extra == timestamp

    def test_no_extra_is_empty(self) -> None:
        assert ZipInfo().carried_extra == b""

    def test_a_malformed_tail_is_refused_not_dropped(self) -> None:
        zi = ZipInfo()
        zi.extra = self._field(0x5455) + b"\xff\xff\x05\x00"
        with pytest.raises(BadZipFile):
            _ = zi.carried_extra


class TestEncryptionFacts:
    @staticmethod
    def _aes(version: int, strength: int = 3) -> ZipInfo:
        zi = ZipInfo()
        zi.flag_bits |= MASK_ENCRYPTED
        zi.aes_extra = WzAesExtra(version, b"AE", strength)
        return zi

    def test_plain_entry(self) -> None:
        zi = ZipInfo()
        assert (zi.encryption_scheme, zi.aes_bits, zi.stores_crc) == (None, None, True)

    def test_zipcrypto_entry_keeps_its_crc(self) -> None:
        zi = ZipInfo()
        zi.flag_bits |= MASK_ENCRYPTED
        assert (zi.encryption_scheme, zi.aes_bits, zi.stores_crc) == (
            ZIP_CRYPTO,
            None,
            True,
        )

    @pytest.mark.parametrize(("strength", "bits"), [(1, 128), (2, 192), (3, 256)])
    def test_aes_strength_is_key_bits(self, strength: int, bits: int) -> None:
        zi = self._aes(WZ_AES_V1, strength)
        assert (zi.encryption_scheme, zi.aes_bits) == (WZ_AES, bits)

    @pytest.mark.parametrize(
        ("fields", "message"),
        [
            ((3, b"AE", 3), "Unsupported WinZip AES version"),
            ((2, b"XX", 3), "Invalid WinZip AES vendor ID"),
            ((2, b"AE", 9), "Invalid WinZip AES strength"),
        ],
    )
    def test_an_invalid_aes_field_cannot_be_built(
        self, fields: tuple[int, bytes, int], message: str
    ) -> None:
        with pytest.raises(ValueError, match=message):
            WzAesExtra(*fields)

    @pytest.mark.parametrize(
        ("version", "stores"), [(WZ_AES_V1, True), (WZ_AES_V2, False)]
    )
    def test_only_aes_1_stores_the_crc(self, version: int, stores: bool) -> None:
        assert self._aes(version).stores_crc is stores
        assert wz_aes_stores_crc(version) is stores
        assert wz_aes_stores_crc(None) is False


class TestUnixMode:
    def test_mode_and_symlink_come_from_the_high_attribute_bits(self) -> None:
        zi = ZipInfo()
        assert (zi.unix_mode, zi.is_symlink()) == (0, False)
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16 | 0x10
        assert (zi.unix_mode, zi.is_symlink()) == (stat.S_IFLNK | 0o777, True)
        zi.external_attr = (stat.S_IFREG | 0o644) << 16
        assert (zi.unix_mode, zi.is_symlink()) == (stat.S_IFREG | 0o644, False)


class TestFromFileFollowSymlinks:
    @pytest.fixture
    def link(self, tmp_path: Path) -> Path:
        (tmp_path / "target.txt").write_bytes(b"x" * 100)
        link = tmp_path / "link"
        try:
            link.symlink_to("target.txt")
        except (OSError, NotImplementedError):
            pytest.skip("symbolic links are not available")
        return link

    def test_follows_by_default(self, link: Path) -> None:
        zi = ZipInfo.from_file(link)
        assert (zi.file_size, zi.is_symlink()) == (100, False)

    def test_describes_the_link_itself_on_request(self, link: Path) -> None:
        zi = ZipInfo.from_file(link, follow_symlinks=False)
        assert zi.file_size == link.lstat().st_size
        assert zi.is_symlink()


def test_bad_source_date_epoch_warning_points_at_writestr_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "soon")
    with zipctl.ZipFile(io.BytesIO(), "w") as zf:
        with pytest.warns(UserWarning, match="SOURCE_DATE_EPOCH") as caught:
            zf.writestr("a.txt", b"x")
    assert caught[0].filename == __file__


def test_empty_unicode_path_warning_points_at_caller() -> None:
    info = ZipInfo("a.txt")
    body = struct.pack("<BL", 1, zlib.crc32(b"a.txt"))
    info.extra = struct.pack("<HH", 0x7075, len(body)) + body
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr(info, b"x")
    with pytest.warns(UserWarning, match="Empty unicode path") as caught:
        zipctl.ZipFile(io.BytesIO(buffer.getvalue())).close()
    assert caught[0].filename == __file__
