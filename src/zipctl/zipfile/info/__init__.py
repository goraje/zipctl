# Friend access inside the zipfile package (ruff exempts it via SLF001).
# pyright: reportPrivateUsage=false
# Import cycle through encoding.py and decoding.py, which only import ZipInfo
# to annotate it.
# pyright: reportImportCycles=false

from __future__ import annotations

import os
import stat
import struct
import sys
import time
import warnings
from collections.abc import Callable
from typing import Protocol

from typing_extensions import override

from zipctl.compression import ZIP_STORED, compressor_names
from zipctl.cryptography import (
    AES_STRENGTH_BITS,
    WZ_AES,
    ZIP_CRYPTO,
    wz_aes_stores_crc,
)
from zipctl.cryptography.aes import EXTRA_WZ_AES
from zipctl.zipfile.info.decoding import (
    decode_extra,
    decode_wz_aes_extra,
    decode_zip64_extra,
)
from zipctl.zipfile.info.encoding import (
    central_directory,
    encode_extra,
    encode_filename_flags,
    file_header,
)
from zipctl.zipfile.info.extra import (
    DD_SIGNATURE,
    EXTRA_NOT_CARRIED,
    EXTRA_ZIP64,
    WzAesExtra,
    _Extra,
    sanitize_filename,
)
from zipctl.zipfile.shared import (
    DEFAULT_VERSION,
    MASK_COMPRESSED_PATCH,
    MASK_ENCRYPTED,
    MASK_STRONG_ENCRYPTION,
    MASK_USE_DATA_DESCRIPTOR,
    MASK_UTF_FILENAME,
)


class _ArchiveDefaults(Protocol):
    """The ``ZipFile`` settings that ``ZipInfo._for_archive`` copies."""

    @property
    def compression(self) -> int: ...

    @property
    def compresslevel(self) -> int | None: ...

    @property
    def _strict_timestamps(self) -> bool: ...


class ZipInfo:
    """Metadata for a single entry in a ZIP archive.

    Instances are created directly or via ``ZipInfo.from_file``, and are
    populated by ``ZipFile`` when reading an archive. Most attributes are set
    from the central directory record; ``header_offset``, ``CRC``, and
    ``raw_time`` are set externally by ``ZipFile`` after parsing.

    Attributes:
        orig_filename: Filename exactly as stored in the ZIP record.
        filename: Normalized filename (null-byte-stripped, forward slashes).
        date_time: Modification time as ``(year, month, day, hour, min, sec)``.
        compress_type: Compression method code (e.g. ``ZIP_STORED``).
        compress_level: Compressor level hint, or ``None`` for the default.
        comment: Per-file comment bytes.
        extra: Raw bytes of the ZIP extra-data block.
        create_system: OS code for the system that created the entry.
        create_version: ZIP specification version used when creating.
        extract_version: Minimum ZIP version needed to extract.
        reserved: Reserved field; must be zero.
        flag_bits: General-purpose bit flags from the local file header.
        volume: Disk number where the file header resides.
        internal_attr: Internal file attributes.
        external_attr: External file attributes (high 16 bits are Unix mode).
        header_offset: Byte offset of the local file header in the archive.
        CRC: CRC-32 of the uncompressed file data.
        compress_size: Compressed file size in bytes.
        file_size: Uncompressed file size in bytes.
        aes_extra: WinZip AES extra-field metadata; see ``WzAesExtra``.
    """

    # Annotate slots that are set externally (by ZipFile) rather than in __init__
    CRC: int  # pyright: ignore[reportUninitializedInstanceVariable]  # set by ZipFile
    header_offset: int  # pyright: ignore[reportUninitializedInstanceVariable]  # set by ZipFile
    raw_time: int  # pyright: ignore[reportUninitializedInstanceVariable]  # set by ZipFile
    _end_offset: int | None

    __slots__: tuple[str, ...] = (
        "orig_filename",
        "filename",
        "date_time",
        "compress_type",
        "compress_level",
        "comment",
        "extra",
        "create_system",
        "create_version",
        "extract_version",
        "reserved",
        "flag_bits",
        "volume",
        "internal_attr",
        "external_attr",
        "header_offset",
        "CRC",
        "compress_size",
        "file_size",
        "raw_time",
        "_end_offset",
        "aes_extra",
        "_stored_filename",
    )

    def __init__(
        self,
        filename: str = "NoName",
        date_time: tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0),
        aes_extra: WzAesExtra | None = None,
    ) -> None:
        """Create a ``ZipInfo`` with the given file name and modification time.

        Args:
            filename: Name of the archive entry. Null bytes are stripped and
                OS path separators are replaced with forward slashes.
            date_time: Modification time as ``(year, month, day, hour, min,
                sec)``. The year must be 1980 or later.
            aes_extra: Pre-populated AES metadata. Defaults to a blank
                ``WzAesExtra()`` (no AES encryption).

        Raises:
            ValueError: If ``date_time[0]`` is earlier than 1980.
        """
        self.orig_filename: str = filename  # Original file name in archive
        self._stored_filename: tuple[bytes, int] | None = None

        # Terminate the file name at the first null byte and
        # ensure paths always use forward slashes as the directory separator.
        filename = sanitize_filename(filename)

        self.filename: str = filename  # Normalized file name
        self.date_time: tuple[int, int, int, int, int, int] = (
            date_time  # year, month, day, hour, min, sec
        )

        if date_time[0] < 1980:
            raise ValueError("ZIP does not support timestamps before 1980")

        # Standard values:
        self.compress_type: int = ZIP_STORED  # Type of compression for the file
        self.compress_level: int | None = None  # Level for the compressor
        self.comment: bytes = b""  # Comment for each file
        self.extra: bytes = b""  # ZIP extra data
        # System which created ZIP archive
        self.create_system: int = 0 if sys.platform == "win32" else 3
        self.create_version: int = DEFAULT_VERSION  # Version which created ZIP archive
        self.extract_version: int = DEFAULT_VERSION  # Version needed to extract archive
        self.reserved: int = 0  # Must be zero
        self.flag_bits: int = 0  # ZIP flag bits
        self.volume: int = 0  # Volume number of file header
        self.internal_attr: int = 0  # Internal attributes
        self.external_attr: int = 0  # External file attributes
        self.compress_size: int = 0  # Size of the compressed file
        self.file_size: int = 0  # Size of the uncompressed file
        self._end_offset = None  # Start of the next local header or central directory
        # Other attributes are set by class ZipFile:
        # header_offset         Byte offset to the file header
        # CRC                   CRC-32 of the uncompressed file
        # AES extra-field metadata; populated by _decode_extra
        # or supplied via aes_extra param
        self.aes_extra: WzAesExtra = (
            aes_extra if aes_extra is not None else WzAesExtra()
        )

    # Maintain backward compatibility with the old protected attribute name.
    @property
    def _compresslevel(self) -> int | None:
        """Alias for ``compress_level``, kept for backward compatibility."""
        return self.compress_level

    @_compresslevel.setter
    def _compresslevel(self, value: int | None) -> None:
        self.compress_level = value

    @override
    def __repr__(self) -> str:
        """Return a human-readable representation of the entry.

        Returns:
            A string of the form ``<ZipInfo filename=... [fields...]>``.
        """
        result = ["<%s filename=%r" % (self.__class__.__name__, self.filename)]
        if self.compress_type != ZIP_STORED:
            result.append(
                " compress_type=%s"
                % compressor_names.get(self.compress_type, self.compress_type)
            )
        hi = self.external_attr >> 16
        lo = self.external_attr & 0xFFFF
        if hi:
            result.append(" filemode=%r" % stat.filemode(hi))
        if lo:
            result.append(" external_attr=%#x" % lo)
        isdir = self.is_dir()
        if not isdir or self.file_size:
            result.append(" file_size=%r" % self.file_size)
        if (not isdir or self.compress_size) and (
            self.compress_type != ZIP_STORED or self.file_size != self.compress_size
        ):
            result.append(" compress_size=%r" % self.compress_size)
        result.append(">")
        return "".join(result)

    @property
    def is_encrypted(self) -> bool:
        """Return ``True`` if the encryption flag is set."""
        return bool(self.flag_bits & MASK_ENCRYPTED)

    @property
    def encryption_scheme(self) -> str | None:
        """``WZ_AES`` or ``ZIP_CRYPTO`` for an encrypted entry, else ``None``."""
        if not self.is_encrypted:
            return None
        return ZIP_CRYPTO if self.aes_extra.wz_aes_strength is None else WZ_AES

    @property
    def aes_bits(self) -> int | None:
        """The AES key size in bits, or ``None`` (not AES, or an unknown strength)."""
        strength = self.aes_extra.wz_aes_strength
        return None if strength is None else AES_STRENGTH_BITS.get(strength)

    @property
    def stores_crc(self) -> bool:
        """Whether the CRC-32 in the headers is the real one (WZ-AES 2 stores 0)."""
        extra = self.aes_extra
        return extra.wz_aes_vendor_id is None or wz_aes_stores_crc(extra.wz_aes_version)

    @property
    def is_utf_filename(self) -> bool:
        """Return ``True`` if filenames are encoded in UTF-8."""
        return bool(self.flag_bits & MASK_UTF_FILENAME)

    @property
    def is_compressed_patch_data(self) -> bool:
        """Return ``True`` if the compressed patch data flag is set."""
        return bool(self.flag_bits & MASK_COMPRESSED_PATCH)

    @property
    def is_strong_encryption(self) -> bool:
        """Return ``True`` if the strong encryption flag is set."""
        return bool(self.flag_bits & MASK_STRONG_ENCRYPTION)

    @property
    def carried_extra(self) -> bytes:
        """The extra fields a copy of this entry keeps.

        Timestamps, owners and the like; the fields the writer builds again (ZIP64,
        WZ-AES) and the Unicode path are left out.  Raises :class:`BadZipFile` if
        the extra data is malformed, which cannot be so for a parsed entry.
        """
        return _Extra.strip(self.extra, EXTRA_NOT_CARRIED)

    @property
    def use_data_descriptor(self) -> bool:
        """Return ``True`` if the data descriptor flag is set."""
        return bool(self.flag_bits & MASK_USE_DATA_DESCRIPTOR)

    @property
    def use_datadescripter(self) -> bool:
        """Compatibility alias for the historical misspelled property."""
        return self.use_data_descriptor

    def get_dosdate(self) -> int:
        """Encode the date part of ``date_time`` as a DOS date word.

        Returns:
            16-bit DOS date value packed as
            ``(year - 1980) << 9 | month << 5 | day``.
        """
        dt = self.date_time
        return (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]

    def get_dostime(self) -> int:
        """Encode the time part of ``date_time`` as a DOS time word.

        Returns:
            16-bit DOS time value packed as
            ``hour << 11 | minute << 5 | (second // 2)``.
        """
        dt = self.date_time
        return dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)

    def encode_data_descriptor(
        self, zip64: bool, crc: int, compress_size: int, file_size: int
    ) -> bytes:
        """Encode a data descriptor record for the given CRC and sizes.

        Args:
            zip64: When ``True``, use 64-bit (Q) fields for the sizes;
                otherwise use 32-bit (L) fields.
            crc: CRC-32 of the uncompressed data.
            compress_size: Compressed size in bytes.
            file_size: Uncompressed size in bytes.

        Returns:
            Packed data descriptor including the ``PK\x07\x08`` signature.
        """
        fmt = "<LLQQ" if zip64 else "<LLLL"
        return struct.pack(fmt, DD_SIGNATURE, crc, compress_size, file_size)

    def data_descriptor(self, zip64: bool) -> bytes:
        """Encode a data descriptor using this entry's stored CRC and sizes.

        Args:
            zip64: When ``True``, use 64-bit fields for the sizes.

        Returns:
            Packed data descriptor including the ``PK\x07\x08`` signature.
        """
        _, crc, _ = self._encode_extra(self.CRC, self.compress_type)
        return self.encode_data_descriptor(
            zip64, crc, self.compress_size, self.file_size
        )

    def encode_datadescripter(
        self, zip64: bool, crc: int, compress_size: int, file_size: int
    ) -> bytes:
        """Compatibility alias for the historical misspelled method."""
        return self.encode_data_descriptor(zip64, crc, compress_size, file_size)

    def datadescripter(self, zip64: bool) -> bytes:
        """Compatibility alias for the historical misspelled method."""
        return self.data_descriptor(zip64)

    def central_directory(self) -> tuple[bytes, bytes, bytes]:
        """Serialize this entry's central directory record.

        Returns:
            A tuple of ``(centdir_bytes, filename_bytes, extra_data_bytes)``
            suitable for writing directly into the central directory.
        """
        return central_directory(self)

    def FileHeader(self, zip64: bool | None = None) -> bytes:
        """Serialize the local file header for this entry.

        Args:
            zip64: Force ZIP64 on (``True``), off (``False``), or auto-detect
                (``None``). Auto-detect enables ZIP64 when either stored size
                exceeds ``ZIP64_LIMIT``.

        Returns:
            Packed local file header followed by the encoded filename and
            extra-data bytes.
        """
        return file_header(self, zip64)

    def _encode_extra(self, crc: int, compress_type: int) -> tuple[bytes, int, int]:
        """Encode the WinZip AES extra field; see :func:`encoding.encode_extra`."""
        return encode_extra(self, crc, compress_type)

    def _encode_filename_flags(self) -> tuple[bytes, int]:
        """Encode the filename and the UTF-8 flag."""
        return encode_filename_flags(self)

    def _decode_zip64_extra(
        self, ln: int, extra: bytes, is_central_directory: bool = True
    ) -> None:
        """Decode a ZIP64 extended information extra field (tag 0x0001)."""
        decode_zip64_extra(self, ln, extra, is_central_directory)

    def _decode_wz_aes_extra(self, ln: int, extra: bytes) -> None:
        """Decode a WinZip AES extra field (tag 0x9901)."""
        decode_wz_aes_extra(self, ln, extra)

    def _decode_extra(self, filename_crc: int) -> None:
        """Parse the extra-data block and update this entry with what it holds."""
        decode_extra(self, filename_crc)

    def _extra_decoders(self) -> dict[int, Callable[..., None]]:
        """Return a mapping of extra-field tag to decoder method.

        Subclasses may override this to register additional decoders for
        vendor-specific or application-defined extra fields.

        Returns:
            A dict mapping each known tag integer to the corresponding bound
            method responsible for decoding that field.
        """
        return {
            EXTRA_ZIP64: self._decode_zip64_extra,
            EXTRA_WZ_AES: self._decode_wz_aes_extra,
        }

    @classmethod
    def from_file(
        cls,
        filename: str | os.PathLike[str],
        arcname: str | os.PathLike[str] | None = None,
        *,
        strict_timestamps: bool = True,
        follow_symlinks: bool = True,
    ) -> ZipInfo:
        """Construct a ``ZipInfo`` from a file or directory on the filesystem.

        Args:
            filename: Path to the file or directory on disk.
            arcname: Name to use inside the archive. Defaults to *filename*
                with the drive letter and leading separators stripped.
            strict_timestamps: When ``False``, timestamps before 1980 are
                clamped to ``1980-01-01`` and timestamps after 2107 are clamped
                to ``2107-12-31`` instead of raising an error.
            follow_symlinks: When ``False``, describe a symbolic link itself
                (``lstat``) rather than what it points to.

        Returns:
            A new ``ZipInfo`` instance with ``file_size`` and ``external_attr``
            populated from the file's ``stat`` result.
        """
        if isinstance(filename, os.PathLike):
            filename = os.fspath(filename)
        st = os.stat(filename) if follow_symlinks else os.lstat(filename)
        isdir = stat.S_ISDIR(st.st_mode)
        mtime = time.localtime(st.st_mtime)
        date_time = mtime[0:6]
        if not strict_timestamps and date_time[0] < 1980:
            date_time = (1980, 1, 1, 0, 0, 0)
        elif not strict_timestamps and date_time[0] > 2107:
            date_time = (2107, 12, 31, 23, 59, 59)
        # Create ZipInfo instance to store file information
        if arcname is None:
            arcname = filename
        elif isinstance(arcname, os.PathLike):
            arcname = os.fspath(arcname)
        arcname = os.path.normpath(os.path.splitdrive(arcname)[1])
        while arcname and arcname[0] in (os.sep, os.altsep):
            arcname = arcname[1:]
        if not arcname:
            raise ValueError("Archive name must not be empty")
        if isdir:
            arcname += "/"
        zinfo = cls(arcname, date_time)
        zinfo.external_attr = (st.st_mode & 0xFFFF) << 16  # Unix attributes
        if isdir:
            zinfo.file_size = 0
            zinfo.external_attr |= 0x10  # MS-DOS directory flag
        else:
            zinfo.file_size = st.st_size

        return zinfo

    def _for_archive(self, archive: _ArchiveDefaults) -> ZipInfo:
        """Populate defaults from *archive* for use with ``ZipFile.writestr``.

        Sets ``date_time`` from the current time (or ``SOURCE_DATE_EPOCH`` when
        defined), copies ``compression`` and ``compresslevel`` from *archive*,
        and assigns appropriate ``external_attr`` permissions.

        Args:
            archive: The ``ZipFile`` instance whose ``compression`` and
                ``compresslevel`` attributes are read.

        Returns:
            ``self``, to allow chained usage.
        """
        # gh-91279: Set the SOURCE_DATE_EPOCH to a specific timestamp
        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        if epoch:
            try:
                get_time = int(epoch)
            except ValueError:
                warnings.warn(
                    f"SOURCE_DATE_EPOCH={epoch!r} is not a valid integer; ignoring",
                    stacklevel=2,
                )
                get_time = int(time.time())
        else:
            get_time = int(time.time())
        try:
            self.date_time = time.localtime(get_time)[:6]
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(
                "SOURCE_DATE_EPOCH is outside the supported timestamp range"
            ) from exc
        if not 1980 <= self.date_time[0] <= 2107:
            if archive._strict_timestamps:
                raise ValueError("ZIP timestamps must be between 1980 and 2107")
            self.date_time = (
                (1980, 1, 1, 0, 0, 0)
                if self.date_time[0] < 1980
                else (2107, 12, 31, 23, 59, 58)
            )

        self.compress_type = archive.compression
        self.compress_level = archive.compresslevel
        if self.filename.endswith("/"):  # pragma: no cover
            self.external_attr = 0o40775 << 16  # drwxrwxr-x
            self.external_attr |= 0x10  # MS-DOS directory flag
        else:
            self.external_attr = 0o600 << 16  # ?rw-------
        return self

    @property
    def unix_mode(self) -> int:
        """The Unix mode kept in the high 16 bits of ``external_attr`` (0: none)."""
        return (self.external_attr >> 16) & 0xFFFF

    def is_symlink(self) -> bool:
        """Return True if this archive member is a symbolic link."""
        return stat.S_ISLNK(self.unix_mode)

    def is_dir(self) -> bool:
        """Return True if this archive member is a directory."""
        if self.filename.endswith("/"):
            return True
        # The ZIP format specification requires to use forward slashes
        # as the directory separator, but in practice some ZIP files
        # created on Windows can use backward slashes.  For compatibility
        # with the extraction code which already handles this:
        if os.path.altsep:
            return self.filename.endswith((os.path.sep, os.path.altsep))
        return False


__all__ = ["ZipInfo", "WzAesExtra"]
