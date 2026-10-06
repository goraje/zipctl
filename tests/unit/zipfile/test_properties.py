"""Property tests: what is written reads back, and damage is always refused cleanly."""

from __future__ import annotations

import io

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import zipctl
from zipctl import ZipFile, ZipFileExtra
from zipctl.compression import registry
from zipctl.exceptions import BadZipFile, PasswordError
from zipctl.limits import ArchiveResourceLimitError

PASSWORD = b"property"


def _available(method: int) -> bool:
    try:
        registry.check_compression(method)
    except (RuntimeError, NotImplementedError):
        return False
    return True


_METHODS = [
    method
    for method in (
        zipctl.ZIP_STORED,
        zipctl.ZIP_DEFLATED,
        zipctl.ZIP_BZIP2,
        zipctl.ZIP_LZMA,
        zipctl.ZIP_ZSTANDARD,
    )
    if _available(method)
]
# (scheme, WinZip AES version)
_PROTECTIONS = [
    (None, None),
    (zipctl.ZIP_CRYPTO, None),
    (zipctl.WZ_AES, 1),
    (zipctl.WZ_AES, 2),
]

# Everything a damaged archive may raise; anything else is a bug.
_REFUSALS = (
    BadZipFile,
    PasswordError,
    ArchiveResourceLimitError,
    NotImplementedError,
)

_members = st.dictionaries(
    st.text(
        st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters="/\\"),
        min_size=1,
        max_size=12,
    ),
    st.binary(max_size=2048),
    min_size=1,
    max_size=4,
)


def _archive(
    members: dict[str, bytes], method: int, protection: tuple[str | None, int | None]
) -> bytes:
    scheme, version = protection
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=method) as zf:
        for name, data in members.items():
            zf.writestr(
                name,
                data,
                encryption=scheme,
                password=PASSWORD if scheme else None,
                extra=ZipFileExtra(force_wz_aes_version=version) if version else None,
            )
    return buffer.getvalue()


@settings(max_examples=150, deadline=None)
@given(
    members=_members,
    method=st.sampled_from(_METHODS),
    protection=st.sampled_from(_PROTECTIONS),
)
def test_what_is_written_reads_back(
    members: dict[str, bytes], method: int, protection: tuple[str | None, int | None]
) -> None:
    data = _archive(members, method, protection)
    with ZipFile(io.BytesIO(data)) as zf:
        assert zf.namelist() == list(members)
        for name, payload in members.items():
            assert zf.read(name, pwd=PASSWORD) == payload


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    members=_members,
    method=st.sampled_from(_METHODS),
    protection=st.sampled_from(_PROTECTIONS),
    damage=st.lists(
        st.tuples(st.integers(min_value=0), st.integers(min_value=1, max_value=255)),
        min_size=1,
        max_size=4,
    ),
    cut=st.one_of(st.none(), st.integers(min_value=0)),
)
def test_a_damaged_archive_is_refused_cleanly(
    members: dict[str, bytes],
    method: int,
    protection: tuple[str | None, int | None],
    damage: list[tuple[int, int]],
    cut: int | None,
) -> None:
    data = bytearray(_archive(members, method, protection))
    for offset, flip in damage:
        data[offset % len(data)] ^= flip
    if cut is not None:
        del data[cut % len(data) :]
    try:
        with ZipFile(io.BytesIO(bytes(data))) as zf:
            for info in zf.infolist():
                zf.read(info, pwd=PASSWORD)
    except _REFUSALS:
        pass
