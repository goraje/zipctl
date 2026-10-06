from __future__ import annotations

import io
import os
import random
import stat
import struct
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from typing_extensions import override

import zipctl
from tests.helpers import NonSeekableBytesIO
from zipctl.compression import lzma, registry
from zipctl.exceptions import BadZipFile, LargeZipFile
from zipctl.zipfile.file import ZipFileExtra
from zipctl.zipfile.file.ext import ZipExtFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.io_wrappers import ClosableZipStream
from zipctl.zipfile.shared import (
    CENTRAL_DIR_SIGNATURE,
    CENTRAL_DIR_SIZE,
    CENTRAL_DIR_STRUCT,
    FILE_HEADER_SIGNATURE,
    FILE_HEADER_SIZE,
    FILE_HEADER_STRUCT,
)


def test_read2_caps_forged_compressed_size_reads() -> None:
    class CountingStream(io.BytesIO):
        requested: int | None = None

        @override
        def read(self, size: int | None = -1) -> bytes:
            requested = -1 if size is None else size
            self.requested = requested
            return b"x" * min(requested, 16)

    stream = CountingStream()
    ext = ZipExtFile.__new__(ZipExtFile)
    ext._fileobj = cast(
        "ClosableZipStream",
        stream,  # pyright: ignore[reportInvalidCast]  # duck-typed stand-in
    )
    ext._compress_left = 1 << 40
    ext._decrypter = None

    data = ext._read2(ZipExtFile.MAX_N)

    assert len(data) == 16
    assert stream.requested == ZipExtFile.MAX_READ_SIZE


def test_aes_version_override_is_validated() -> None:
    with pytest.raises(ValueError, match="must be 1 or 2"):
        ZipFileExtra(force_wz_aes_version=3)


def test_lzma_oversized_dictionary_is_rejected() -> None:
    if lzma.compression_entry is None:
        pytest.skip("lzma not available")

    props = bytes([0x5D]) + struct.pack("<I", 1 << 31)
    with pytest.raises(BadZipFile, match="dictionary size"):
        lzma._lzma1_filter_from_props(props)


def _find_aes_metadata(archive: bytes) -> tuple[int, int, int, int]:
    local_offset = archive.index(FILE_HEADER_SIGNATURE)
    local = struct.unpack(
        FILE_HEADER_STRUCT,
        archive[local_offset : local_offset + FILE_HEADER_SIZE],
    )
    local_name_len, local_extra_len = local[10:12]
    local_extra_start = local_offset + FILE_HEADER_SIZE + local_name_len
    local_extra = archive[local_extra_start : local_extra_start + local_extra_len]

    central_offset = archive.index(CENTRAL_DIR_SIGNATURE)
    central = struct.unpack(
        CENTRAL_DIR_STRUCT,
        archive[central_offset : central_offset + CENTRAL_DIR_SIZE],
    )
    central_name_len, central_extra_len = central[12:14]
    central_extra_start = central_offset + CENTRAL_DIR_SIZE + central_name_len
    central_extra = archive[
        central_extra_start : central_extra_start + central_extra_len
    ]

    def version(extra: bytes) -> int:
        marker = struct.pack("<HH", 0x9901, 7)
        start = extra.index(marker) + 4
        return int(struct.unpack("<H", extra[start : start + 2])[0])

    return local[7], central[9], version(local_extra), version(central_extra)


@pytest.mark.parametrize(
    "compression",
    [zipctl.ZIP_DEFLATED, zipctl.ZIP_BZIP2, zipctl.ZIP_LZMA],
)
def test_truncated_compressed_member_raises(tmp_path: Path, compression: int) -> None:
    if not registry._registry.get(compression):
        pytest.skip("compression method unavailable")

    path = tmp_path / f"truncated-{compression}.zip"
    with zipctl.ZipFile(path, "w", compression=compression) as zf:
        zf.writestr("payload.bin", random.Random(0).randbytes(4096))
    archive = bytearray(path.read_bytes())

    # Shorten the recorded compressed size in both headers: the bytes left over
    # are refused on open, or else the truncation is hit while reading.
    central_offset = archive.index(CENTRAL_DIR_SIGNATURE)
    (compress_size,) = struct.unpack_from("<L", archive, central_offset + 20)
    struct.pack_into("<L", archive, central_offset + 20, compress_size - 30)
    struct.pack_into("<L", archive, 18, compress_size - 30)
    path.write_bytes(archive)

    with pytest.raises(BadZipFile), zipctl.ZipFile(path) as zf:
        zf.read("payload.bin")


def test_crc_mismatch_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "crc.zip"
    with zipctl.ZipFile(path, "w") as zf:
        zf.writestr("payload.bin", b"payload")
    archive = bytearray(path.read_bytes())
    central_offset = archive.index(CENTRAL_DIR_SIGNATURE)
    # both headers agree on the wrong CRC, so only the data check can catch it
    archive[14:18] = struct.pack("<L", 0)
    archive[central_offset + 16 : central_offset + 20] = struct.pack("<L", 0)
    path.write_bytes(archive)

    with pytest.raises(BadZipFile, match="Bad CRC-32"):
        with zipctl.ZipFile(path) as zf:
            zf.read("payload.bin")


@pytest.mark.parametrize("compression", [zipctl.ZIP_STORED, zipctl.ZIP_DEFLATED])
@pytest.mark.parametrize("payload", [b"x", b"x" * 8192])
def test_aes_headers_have_consistent_v2_metadata(
    tmp_path: Path,
    compression: int,
    payload: bytes,
) -> None:
    path = tmp_path / f"aes-{compression}-{len(payload)}.zip"
    with zipctl.ZipFile(
        path, "w", compression=compression, encryption=zipctl.WZ_AES
    ) as zf:
        zf.setpassword(b"password")
        zf.writestr("payload.bin", payload)

    local_crc, central_crc, local_version, central_version = _find_aes_metadata(
        path.read_bytes()
    )
    assert local_crc == central_crc == 0
    assert local_version == central_version == zipctl.WZ_AES_V2


def test_aes_v1_headers_preserve_crc(tmp_path: Path) -> None:
    path = tmp_path / "aes-v1.zip"
    payload = b"compatibility payload"
    with zipctl.ZipFile(
        path,
        "w",
        encryption=zipctl.WZ_AES,
        extra=zipctl.ZipFileExtra(force_wz_aes_version=1),
    ) as zf:
        zf.setpassword(b"password")
        zf.writestr("payload.bin", payload)

    local_crc, central_crc, local_version, central_version = _find_aes_metadata(
        path.read_bytes()
    )
    assert local_crc == central_crc
    assert local_crc != 0
    assert local_version == central_version == zipctl.WZ_AES_V1


def test_aes_output_works_on_non_seekable_stream() -> None:
    buffer = NonSeekableBytesIO()
    with zipctl.ZipFile(buffer, "w", encryption=zipctl.WZ_AES) as zf:
        zf.setpassword(b"password")
        zf.writestr("payload.bin", b"payload")

    with zipctl.ZipFile(io.BytesIO(buffer.getvalue())) as zf:
        zf.setpassword(b"password")
        assert zf.read("payload.bin") == b"payload"


def test_aes_v2_data_descriptor_zeroes_crc() -> None:
    buffer = NonSeekableBytesIO()
    with zipctl.ZipFile(buffer, "w", encryption=zipctl.WZ_AES) as zf:
        zf.setpassword(b"password")
        zf.writestr("payload.bin", b"payload")

    data = buffer.getvalue()
    offset = data.index(b"PK\x07\x08")
    _, crc, _, _ = struct.unpack_from("<LLLL", data, offset)
    assert crc == 0


def _symlink_archive(path: Path, name: str, target: str) -> None:
    info = ZipInfo(name)
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipctl.ZipFile(path, "w") as zf:
        zf.writestr(info, target)


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_symlink_member_over_existing_directory_raises_extraction_error(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "link.zip"
    _symlink_archive(archive, "victim", "elsewhere")
    dest = tmp_path / "dest"
    (dest / "victim").mkdir(parents=True)

    with zipctl.ZipFile(archive) as zf:
        with pytest.raises(zipctl.ExtractionError):
            zf.extractall(dest)
    assert (dest / "victim").is_dir()


def test_file_member_over_existing_directory_raises_extraction_error(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "file.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("victim", b"data")
    dest = tmp_path / "dest"
    (dest / "victim").mkdir(parents=True)

    with zipctl.ZipFile(archive) as zf:
        with pytest.raises(zipctl.ExtractionError):
            zf.extractall(dest)
    assert (dest / "victim").is_dir()


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_extract_refuses_symlinked_intermediate_directory(tmp_path: Path) -> None:
    archive = tmp_path / "nested.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("sub/inner.txt", b"data")
    dest = tmp_path / "dest"
    outside = tmp_path / "outside"
    dest.mkdir()
    outside.mkdir()
    (dest / "sub").symlink_to(outside, target_is_directory=True)

    with zipctl.ZipFile(archive) as zf:
        with pytest.raises(zipctl.ExtractionError) as excinfo:
            zf.extractall(dest)
    codes = [v.code for v in excinfo.value.result.violations]
    # found by assessment, before any write
    assert codes == ["outside_root", "symlink_parent"]
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="needs symlinks")
def test_a_path_through_an_archived_symlink_is_refused_before_writing(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "through.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        link = zipctl.ZipInfo("l")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, b"sub")
        zf.writestr("sub/", b"")
        zf.writestr("l/x", b"x")
    dest = tmp_path / "dest"

    with zipctl.ZipFile(archive) as zf, pytest.raises(zipctl.ExtractionError) as exc:
        zf.safe_extractall(dest, policy=zipctl.ExtractPolicy(allow_symlinks=True))
    assert "symlink_parent" in [v.code for v in exc.value.result.violations]
    assert not dest.exists() or list(dest.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
@pytest.mark.parametrize("use_policy", [False, True])
def test_extract_into_destination_reached_through_symlink(
    tmp_path: Path, use_policy: bool
) -> None:
    archive = tmp_path / "a.zip"
    with zipctl.ZipFile(archive, "w") as zf:
        zf.writestr("dir/file.txt", b"data")
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with zipctl.ZipFile(archive) as zf:
        if use_policy:
            zf.safe_extractall(link, policy=zipctl.ExtractPolicy())
        else:
            zf.extractall(link)
    assert (real / "dir" / "file.txt").read_bytes() == b"data"


def _open_failure_password_without_encryption(zf: zipctl.ZipFile) -> None:
    zf.open("bad.txt", "w", password=b"secret")


def _open_failure_missing_password(zf: zipctl.ZipFile) -> None:
    zf.open("bad.txt", "w", encryption=zipctl.WZ_AES)


def _open_failure_zip64_required(zf: zipctl.ZipFile) -> None:
    info = ZipInfo("huge.bin")
    info.file_size = 1 << 32
    zf.open(info, "w")


@pytest.mark.parametrize(
    ("failing_open", "error"),
    [
        (_open_failure_password_without_encryption, ValueError),
        (_open_failure_missing_password, RuntimeError),
        (_open_failure_zip64_required, LargeZipFile),
    ],
)
def test_failed_open_for_write_does_not_lock_the_archive(
    failing_open: Callable[[zipctl.ZipFile], None], error: type[Exception]
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w", allowZip64=False) as zf:
        zf.writestr("before.txt", b"before")
        with pytest.raises(error):
            failing_open(zf)
        zf.writestr("after.txt", b"after")

    with zipctl.ZipFile(io.BytesIO(buffer.getvalue())) as zf:
        assert zf.namelist() == ["before.txt", "after.txt"]
        assert zf.read("after.txt") == b"after"


def _write_duplicates(archive: Path) -> None:
    with zipctl.ZipFile(archive, "w") as zf:
        for name in ("same.txt", "./same.txt", "a/../same.txt"):
            zf.writestr(name, b"x")
        zf.writestr("other.txt", b"y")


def test_assess_reports_each_duplicate_target_once(tmp_path: Path) -> None:
    archive = tmp_path / "dups.zip"
    _write_duplicates(archive)

    with zipctl.ZipFile(archive) as zf:
        assessment = zf.assess(tmp_path / "out")
    assert assessment.duplicate_targets == ((tmp_path / "out" / "same.txt").resolve(),)


def _one_member_archive(info: ZipInfo | str = "a.txt") -> bytearray:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr(info, b"hello")
    return bytearray(buffer.getvalue())


def test_negative_local_header_offset_is_bad_zip_file() -> None:
    data = _one_member_archive()
    end = data.rfind(b"PK\x05\x06")
    (start_dir,) = struct.unpack_from("<I", data, end + 16)
    # A directory said to start past where it is makes the prepended size -10.
    struct.pack_into("<I", data, end + 16, start_dir + 10)
    with pytest.raises(BadZipFile, match="Bad offset for local file header"):
        zipctl.ZipFile(io.BytesIO(bytes(data)))


def test_duplicate_known_extra_field_is_refused() -> None:
    info = ZipInfo("a.txt")
    unicode_path = struct.pack("<BL", 1, zlib.crc32(b"a.txt")) + b"b.txt"
    field = struct.pack("<HH", 0x7075, len(unicode_path)) + unicode_path
    info.extra = field + field
    data = _one_member_archive(info)
    with pytest.raises(BadZipFile, match="Duplicate extra field 7075"):
        zipctl.ZipFile(io.BytesIO(bytes(data)))


def test_local_header_carries_the_user_extra_fields() -> None:
    info = ZipInfo("a.txt")
    info.extra = struct.pack("<HH2s", 0xCAFE, 2, b"ok")
    data = _one_member_archive(info)
    (local_extra_length,) = struct.unpack_from("<H", data, 28)
    name_length = len("a.txt")
    local_extra = data[FILE_HEADER_SIZE + name_length :][:local_extra_length]
    assert bytes(local_extra) == info.extra
    with zipctl.ZipFile(io.BytesIO(bytes(data))) as zf:
        assert zf.read("a.txt") == b"hello"
        assert zf.getinfo("a.txt").extra == info.extra


def test_a_root_directory_entry_extracts_as_a_no_op(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.mkdir("./")
        zf.writestr("a.txt", b"a")
    with zipctl.ZipFile(buffer) as zf:
        zf.extractall(tmp_path / "plain")
        zf.safe_extractall(tmp_path / "policy")
    assert (tmp_path / "plain" / "a.txt").read_bytes() == b"a"
    assert (tmp_path / "policy" / "a.txt").read_bytes() == b"a"


def test_an_entry_whose_with_block_raises_is_not_committed() -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:

        def produce() -> None:
            with zf.open("half.txt", "w") as dest:
                dest.write(b"partial")
                raise RuntimeError("producer failed")

        with pytest.raises(RuntimeError):
            produce()
        zf.writestr("ok.txt", b"ok")
    with zipctl.ZipFile(buffer) as zf:
        assert zf.namelist() == ["ok.txt"]
        assert zf.read("ok.txt") == b"ok"


def test_exactly_0xffff_entries_get_a_zip64_end_record() -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        for i in range(0xFFFF):
            zf.writestr(f"{i}", b"")
    data = buffer.getvalue()
    assert b"PK\x06\x06" in data
    with zipctl.ZipFile(io.BytesIO(data)) as zf:
        assert len(zf.infolist()) == 0xFFFF


def test_local_and_central_unicode_paths_must_agree() -> None:
    name = "caf\xe9.txt"
    raw = b"cafe.txt"
    good = struct.pack("<HHBL", 0x7075, 5 + len(name.encode()), 1, zlib.crc32(raw))
    good += name.encode()
    bad = struct.pack("<HHBL", 0x7075, 5 + 9, 1, zlib.crc32(raw)) + b"other.txt"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        info = zipfile.ZipInfo(raw.decode())
        info.extra = good
        zf.writestr(info, b"x")
    data = bytearray(buffer.getvalue())
    local = data.find(good)
    assert local != -1
    assert data.find(good, local + 1) != -1
    data[local : local + len(good)] = bad.ljust(len(good), b"\0")[: len(good)]
    with pytest.raises(BadZipFile), zipctl.ZipFile(io.BytesIO(bytes(data))) as zf:
        zf.read(zf.infolist()[0])


def test_an_unsupported_method_is_a_violation_not_a_crash(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.writestr("ok.txt", b"ok")
        zf.writestr("odd.bin", b"odd")
    data = bytearray(buffer.getvalue())
    for signature, offset in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
        start = data.find(signature)
        start = data.find(signature, start + 1)  # the second member
        struct.pack_into("<H", data, start + offset, 98)  # PPMd
    with (
        zipctl.ZipFile(io.BytesIO(bytes(data))) as zf,
        pytest.raises(zipctl.ExtractionError) as excinfo,
    ):
        zf.safe_extractall(tmp_path)
    codes = {v.member: v.code for v in excinfo.value.result.violations}
    assert codes == {"odd.bin": "unsupported", "ok.txt": "archive_refused"}
    assert not (tmp_path / "ok.txt").exists()
    assert not (tmp_path / "odd.bin").exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_a_fifo_never_gets_setuid_from_the_archive(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        info = ZipInfo("pipe")
        info.external_attr = (stat.S_IFIFO | stat.S_ISUID | 0o640) << 16
        zf.writestr(info, b"")
    with zipctl.ZipFile(buffer) as zf:
        zf.safe_extractall(
            tmp_path, policy=zipctl.ExtractPolicy(allow_special_files=True)
        )
    assert not (tmp_path / "pipe").stat().st_mode & stat.S_ISUID


@pytest.mark.parametrize("target", ["C:evil", "\\\\server\\share", "\\rooted"])
def test_windows_style_symlink_targets_are_refused_everywhere(
    tmp_path: Path, target: str
) -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        info = ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, target)
    with (
        zipctl.ZipFile(buffer) as zf,
        pytest.raises(zipctl.ExtractionError) as excinfo,
    ):
        zf.safe_extractall(tmp_path, policy=zipctl.ExtractPolicy(allow_symlinks=True))
    assert excinfo.value.result.extracted_count == 0
    assert not os.path.lexists(tmp_path / "link")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("CON", "_CON"),
        ("dir/nul.txt", "dir\\_nul.txt"),
        ("COM1.log", "_COM1.log"),
        ("console.txt", "console.txt"),
    ],
)
def test_windows_device_names_are_prefixed(name: str, expected: str) -> None:
    from zipctl.zipfile.validators import _sanitize_windows_name

    assert _sanitize_windows_name(name.replace("/", "\\"), "\\") == expected


def _streamed_archive() -> bytearray:
    """One member written to an unseekable stream, so it has a data descriptor."""
    out = NonSeekableBytesIO()
    with zipctl.ZipFile(out, "w") as zf:
        zf.writestr("a.txt", b"hello")
    return bytearray(out.getvalue())


def test_data_after_the_end_record_is_refused() -> None:
    data = _one_member_archive() + b"trailing junk"
    with pytest.raises(BadZipFile, match="Data after the end"):
        zipctl.ZipFile(io.BytesIO(bytes(data)))


def test_bytes_between_entries_are_refused() -> None:
    data = _one_member_archive()
    end = data.rfind(b"PK\x05\x06")
    start_dir = data.find(CENTRAL_DIR_SIGNATURE)
    gap = b"hidden"
    data[start_dir:start_dir] = gap
    struct.pack_into("<L", data, end + len(gap) + 16, start_dir + len(gap))
    with pytest.raises(BadZipFile, match="Unaccounted bytes after 'a.txt'"):
        zipctl.ZipFile(io.BytesIO(bytes(data)))


def test_an_apk_signing_block_before_the_directory_is_accepted() -> None:
    data = _one_member_archive()
    end = data.rfind(b"PK\x05\x06")
    start_dir = data.find(CENTRAL_DIR_SIGNATURE)
    pairs = struct.pack("<QL", 8, 0x7109871A) + bytes(4)
    size = len(pairs) + 8 + 16  # everything after the first size field
    block = struct.pack("<Q", size) + pairs + struct.pack("<Q", size)
    block += b"APK Sig Block 42"
    data[start_dir:start_dir] = block
    struct.pack_into("<L", data, end + len(block) + 16, start_dir + len(block))
    with zipctl.ZipFile(io.BytesIO(bytes(data))) as zf:
        assert zf.read("a.txt") == b"hello"


def test_a_data_descriptor_must_match_the_central_directory() -> None:
    data = _streamed_archive()
    with zipctl.ZipFile(io.BytesIO(bytes(data))) as zf:
        assert zf.read("a.txt") == b"hello"
    descriptor = data.find(b"PK\x07\x08")
    data[descriptor + 4] ^= 0xFF  # its CRC
    with zipctl.ZipFile(io.BytesIO(bytes(data))) as zf:
        with pytest.raises(BadZipFile, match="Data descriptor and central"):
            zf.read("a.txt")


def test_backslashes_are_separators_on_every_platform() -> None:
    info = ZipInfo("dir\\sub\\")
    assert info.filename == "dir/sub/"
    assert info.is_dir()


def _two_member_archive() -> bytearray:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as archive:
        archive.writestr("a", b"a")
        archive.writestr("b", b"b")
    return bytearray(buffer.getvalue())


@pytest.mark.parametrize("offset", [0xFFFFFFF0, 0])
def test_a_local_header_offset_out_of_place_is_refused_at_open(offset: int) -> None:
    data = _two_member_archive()
    second = data.rfind(CENTRAL_DIR_SIGNATURE)
    struct.pack_into("<I", data, second + 42, offset)  # past the directory, or shared
    with pytest.raises(BadZipFile, match="Bad offset"):
        zipctl.ZipFile(io.BytesIO(bytes(data)))


def test_an_archive_with_a_stub_stays_readable_after_appending() -> None:
    buffer = io.BytesIO(b"#!stub\n" + bytes(_two_member_archive()))
    with zipctl.ZipFile(buffer, "a", allow_prepended_data=True) as archive:
        archive.writestr("c", b"c")
    with zipctl.ZipFile(buffer, allow_prepended_data=True) as reread:
        assert [reread.read(name) for name in "abc"] == [b"a", b"b", b"c"]
    with pytest.raises(BadZipFile, match="Unaccounted bytes"):
        zipctl.ZipFile(buffer)


def test_is_zipfile_is_false_for_a_directory_before_the_file_start() -> None:
    data = _two_member_archive()
    struct.pack_into("<I", data, len(data) - 10, len(data) * 2)  # directory size
    assert zipctl.is_zipfile(io.BytesIO(bytes(data))) is False


def _deflated_member(payload: bytes, stream: bytes, declared_size: int) -> bytes:
    """One deflated member holding *stream*, claiming *payload* of *declared_size*."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("m", stream)  # stored, then relabelled as deflated
    data = bytearray(buffer.getvalue())
    crc = zlib.crc32(payload)
    for start, fields in ((0, 8), (data.rfind(CENTRAL_DIR_SIGNATURE), 10)):
        struct.pack_into("<H", data, start + fields, zipfile.ZIP_DEFLATED)
        struct.pack_into("<I", data, start + fields + 6, crc)
        struct.pack_into("<I", data, start + fields + 14, declared_size)
    return bytes(data)


def _raw_deflate(payload: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(payload) + compressor.flush()


def test_bytes_after_the_end_of_a_deflate_stream_are_refused() -> None:
    payload = b"payload" * 10
    stream = _raw_deflate(payload) + b"smuggled"
    with zipctl.ZipFile(
        io.BytesIO(_deflated_member(payload, stream, len(payload)))
    ) as zf:
        assert zf.testzip() == "m"
        with pytest.raises(BadZipFile, match="after the end"):
            zf.read("m")


def test_inflating_stops_near_the_declared_size() -> None:
    import tracemalloc

    payload = bytes(64 << 20)
    member = _deflated_member(payload, _raw_deflate(payload), 10)
    with zipctl.ZipFile(io.BytesIO(member)) as zf, zf.open("m") as handle:
        tracemalloc.start()
        try:
            with pytest.raises(BadZipFile, match="More data"):
                handle.read(1 << 30)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
    assert peak < 4 << 20


def test_rewinding_a_stored_member_keeps_the_crc_check() -> None:
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as archive:
        archive.writestr("m", b"payload" * 100)
    data = bytearray(buffer.getvalue())
    data[FILE_HEADER_SIZE + 1 + 10] ^= 1  # a payload byte, past the name "m"
    with zipctl.ZipFile(io.BytesIO(bytes(data))) as zf, zf.open("m") as handle:
        handle.seek(0, os.SEEK_END)
        handle.seek(0)
        with pytest.raises(BadZipFile, match="CRC"):
            handle.read()


def test_appending_writes_over_an_apk_signing_block() -> None:
    data = _one_member_archive()
    end = data.rfind(b"PK\x05\x06")
    start_dir = data.find(CENTRAL_DIR_SIGNATURE)
    pairs = struct.pack("<QL", 8, 0x7109871A) + bytes(4)
    size = len(pairs) + 8 + 16
    block = struct.pack("<Q", size) + pairs + struct.pack("<Q", size)
    block += b"APK Sig Block 42"
    data[start_dir:start_dir] = block
    struct.pack_into("<L", data, end + len(block) + 16, start_dir + len(block))
    buf = io.BytesIO(bytes(data))
    with zipctl.ZipFile(buf, "a") as zf:
        zf.writestr("b.txt", b"more")
    with zipctl.ZipFile(io.BytesIO(buf.getvalue())) as zf:
        assert zf.read("a.txt") == b"hello"
        assert zf.read("b.txt") == b"more"


def test_a_unicode_path_field_in_the_central_directory_only_is_read() -> None:
    data = _one_member_archive()
    end = data.rfind(b"PK\x05\x06")
    start_dir = data.find(CENTRAL_DIR_SIGNATURE)
    name = "é.txt".encode()
    body = b"\x01" + struct.pack("<L", zlib.crc32(b"a.txt")) + name
    field = struct.pack("<HH", 0x7075, len(body)) + body
    extra_at = start_dir + 46 + len(b"a.txt")
    data[extra_at:extra_at] = field
    struct.pack_into("<H", data, start_dir + 30, len(field))
    end += len(field)
    cd_size = struct.unpack_from("<L", data, end + 12)[0]
    struct.pack_into("<L", data, end + 12, cd_size + len(field))
    with zipctl.ZipFile(io.BytesIO(bytes(data))) as zf:
        assert zf.namelist() == ["é.txt"]
        assert zf.read("é.txt") == b"hello"


def test_an_exception_on_an_unseekable_output_is_not_replaced() -> None:
    def write() -> None:
        with zipctl.ZipFile(NonSeekableBytesIO(), "w") as zf:
            writer = zf.open("e", "w")
            writer.write(b"hi")
            raise KeyError("mine")

    with pytest.raises(KeyError, match="mine"):
        write()
