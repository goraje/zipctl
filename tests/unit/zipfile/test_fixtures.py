"""Archives written by other tools, committed so they are read on every run."""

from __future__ import annotations

import zlib
from pathlib import Path

import pytest

from zipctl import BadPassword, ZipFile

FIXTURES = Path(__file__).parent.parent.parent / "fixtures"
LINES = "".join(f"line {i} of the fixture\n" for i in range(400)).encode()


def test_lzma_without_an_end_marker_is_read_to_its_declared_size() -> None:
    # 7-Zip: 7zz a -tzip -mm=LZMA:eos=off (general purpose flag bit 1 clear)
    with ZipFile(FIXTURES / "lzma-without-eos.zip") as zf:
        info = zf.getinfo("small.txt")
        assert not info.flag_bits & 0x2
        assert zf.read(info) == LINES
        assert info.CRC == zlib.crc32(LINES)


@pytest.mark.parametrize(
    ("archive", "name", "flags", "aes_version"),
    [
        # 7zz a -tzip -mem=AES256 -pfixture
        ("aes256-7zip.zip", "small.txt", 0x1, 2),
        # 7zz a -tzip -mem=ZipCrypto -pfixture
        ("zipcrypto-7zip.zip", "small.txt", 0x1, None),
        # cat small.txt | zip -P fixture - -  (Info-ZIP, streamed: data descriptor)
        ("zipcrypto-infozip-stream.zip", "-", 0x9, None),
    ],
)
def test_encrypted_archives_from_other_tools_are_read(
    archive: str, name: str, flags: int, aes_version: int | None
) -> None:
    with ZipFile(FIXTURES / archive) as zf:
        info = zf.getinfo(name)
        assert info.flag_bits == flags
        assert getattr(info.aes_extra, "wz_aes_version", None) == aes_version
        assert zf.read(info, pwd=b"fixture") == LINES
        with pytest.raises(BadPassword):
            zf.read(info, pwd=b"wrong")
