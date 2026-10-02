"""The :class:`ZipFile` archive class and the :func:`is_zipfile` helper."""

from __future__ import annotations

import os
import shutil
import warnings
from collections.abc import Iterable
from functools import partial
from types import TracebackType
from typing import IO, TYPE_CHECKING, Literal, TypeAlias, cast, overload

from typing_extensions import override

if TYPE_CHECKING:
    from typing_extensions import Self
else:
    try:
        from typing import Self
    except ImportError:  # Python < 3.11
        from typing_extensions import Self

if TYPE_CHECKING:
    from zipctl.cryptography.base import BaseZipEncryptor

from zipctl.compression import (
    ZIP_STORED,
    Registry,
    registry,
)
from zipctl.exceptions import BadZipFile
from zipctl.limits import ArchiveLimits
from zipctl.zipfile.assessment import (
    ArchiveAssessment,
)
from zipctl.zipfile.assessor import (
    assess_archive,
    default_assessment_policy,
)
from zipctl.zipfile.extract import (
    ExtractionError,
    ExtractMemberResult,
    ExtractPolicy,
    ExtractResult,
)
from zipctl.zipfile.file.directory import CentralDirectory
from zipctl.zipfile.file.encryption import (
    INHERIT_ENCRYPTION,
    EncryptionOverride,
    EncryptionSettings,
    ZipFileExtra,
    require_bytes,
)
from zipctl.zipfile.file.extraction import (
    PasswordProvider,
    extract_all_with_progress,
    extract_member,
    extract_members_with_policy,
)
from zipctl.zipfile.file.reader import ArchiveReader
from zipctl.zipfile.file.stream import ArchiveStream
from zipctl.zipfile.file.writer import ArchiveWriter
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.inspection import (
    InspectionMember,
    InspectionResult,
    build_inspection_result,
)
from zipctl.zipfile.password import (
    MemberPasswordCheck,
    PasswordCheckResult,
    check_member_password,
)
from zipctl.zipfile.progress import (
    ProgressCallback,
)
from zipctl.zipfile.records import looks_like_zip
from zipctl.zipfile.shared import (
    ZIP_MAX_COMMENT,
    ReadWriteMode,
    StrPath,
)

__all__ = [
    "ZipFile",
    "PasswordProvider",
    "is_zipfile",
    "INHERIT_ENCRYPTION",
    "EncryptionOverride",
    "ZipFileExtra",
    "InspectionMember",
    "InspectionResult",
]

_ZipFileMode: TypeAlias = Literal["r", "w", "x", "a"]


def is_zipfile(filename: StrPath | IO[bytes]) -> bool:
    """Return ``True`` if *filename* is a valid ZIP file based on its magic number.

    Args:
        filename: Path to the file on disk, or an open binary file-like object.
            File-like objects are sought back to their original position after
            inspection.

    Returns:
        ``True`` if the file looks like a ZIP archive, ``False`` otherwise.
    """
    result = False
    try:
        if not isinstance(filename, (str, os.PathLike)):
            pos = filename.tell()
            try:
                result = looks_like_zip(filename)
            finally:
                filename.seek(pos)
        else:
            with open(filename, "rb") as fp:
                result = looks_like_zip(fp)
    except (OSError, BadZipFile):
        pass
    return result


class ZipFile:
    """Read, write, and append ZIP archives.

    Supports standard ZIP compression (stored, deflate, bzip2, lzma, zstd),
    optional WinZip AES (``WZ_AES``) and traditional ZIP encryption
    (``ZIP_CRYPTO``), ZIP64 extensions, and archive comments.

    The work is shared out: an :class:`ArchiveStream` owns the file, a
    :class:`CentralDirectory` the entries, :class:`EncryptionSettings` the
    defaults for encryption, an :class:`ArchiveReader` opens members to read
    and an :class:`ArchiveWriter` adds them.  This class keeps the
    ``zipfile``-compatible surface over them.

    Attributes:
        fp: The underlying binary file object, or ``None`` when closed.
        debug: Verbosity level for diagnostic output (0–3).
        NameToInfo: Mapping of archive member name to its ZipInfo.
        filelist: Ordered list of ZipInfo entries.
        compression: Default compression method for new entries.
        compresslevel: Default compression level for new entries.
        mode: The mode the archive was opened with (``'r'``, ``'w'``,
            ``'x'``, or ``'a'``).
        pwd: Default decryption password, or ``None``.
        encryption: Encryption scheme (``WZ_AES``, ``ZIP_CRYPTO``, or
            ``None``).
        metadata_encoding: Encoding used to decode non-UTF-8 filenames on
            read. ``None`` defaults to ``'cp437'``.
    """

    def __init__(
        self,
        file: StrPath | IO[bytes],
        mode: _ZipFileMode = "r",
        compression: int = ZIP_STORED,
        allowZip64: bool = True,
        compresslevel: int | None = None,
        *,
        strict_timestamps: bool = True,
        metadata_encoding: str | None = None,
        encryption: str | None = None,
        extra: ZipFileExtra | None = None,
        compression_registry: Registry | None = None,
        limits: ArchiveLimits | None = None,
    ) -> None:
        """Open a ZIP archive for reading, writing, exclusive creation, or appending.

        Args:
            file: Path to the archive file, or an open binary file-like object.
            mode: ``'r'`` to read, ``'w'`` to create/overwrite, ``'x'`` to
                create exclusively (fail if the file exists), or ``'a'`` to
                append.
            compression: Default compression method for entries added with
                :meth:`write` or :meth:`writestr`. Defaults to ``ZIP_STORED``.
            allowZip64: When ``True`` (the default), emit ZIP64 extensions for
                files or archives that exceed the 4 GiB / 65535-entry limits.
            compresslevel: Default compressor level hint, or ``None`` for the
                compressor's own default.
            strict_timestamps: When ``False``, timestamps outside the range
                1980–2107 are clamped rather than raising an error.
            metadata_encoding: Encoding for non-UTF-8 member names when
                reading. ``None`` defaults to ``'cp437'``. Only valid with
                mode ``'r'``.
            encryption: Encryption scheme to apply when writing (``WZ_AES``
                or ``ZIP_CRYPTO``). Requires :meth:`setpassword` before
                writing.
            extra: Additional settings; see :class:`ZipFileExtra`.
            limits: Parser and built-in decoder budgets; see :class:`ArchiveLimits`.

        Raises:
            ValueError: If *mode* is invalid, *metadata_encoding* is supplied
                with a non-read mode, or the compression method is unsupported.
            BadZipFile: If *mode* is ``'r'`` or ``'a'`` and the file is not a
                valid ZIP archive.
        """
        if mode not in ("r", "w", "x", "a"):
            raise ValueError("ZipFile requires mode 'r', 'w', 'x', or 'a'")  # pyright: ignore[reportUnreachable]
        if metadata_encoding and mode != "r":
            raise ValueError("metadata_encoding is only supported for reading files")
        selected_registry = (compression_registry or registry).copy()
        selected_registry.check_compression(compression)

        self.debug: int = 0
        self.compression: int = compression
        self.compresslevel: int | None = compresslevel
        self.mode: _ZipFileMode = mode
        self.metadata_encoding: str | None = metadata_encoding
        self.limits: ArchiveLimits = limits or ArchiveLimits()
        self._strict_timestamps: bool = strict_timestamps

        self._stream: ArchiveStream = ArchiveStream(file, mode)
        self._directory: CentralDirectory = CentralDirectory()
        self._encryption: EncryptionSettings = EncryptionSettings(encryption, extra)
        self._writer: ArchiveWriter = ArchiveWriter(
            mode,
            self._stream,
            self._directory,
            self._encryption,
            selected_registry,
            allow_zip64=allowZip64,
        )
        self._reader: ArchiveReader = ArchiveReader(
            self._stream,
            self._writer,
            self._encryption,
            selected_registry,
            self.limits,
            metadata_encoding,
        )
        try:
            self._start(mode)
        except BaseException:
            self._stream.close()
            raise

    def _start(self, mode: _ZipFileMode) -> None:
        """Read the directory, or position a new archive, as *mode* requires."""
        fp = self._stream.require_open("open")
        if mode == "r":
            self._load_directory(fp)
        elif mode in ("w", "x"):
            self._directory.start_dir = self._stream.start_writing()
            self._directory.modified = True
        else:
            try:
                self._load_directory(fp)
                fp.seek(self._directory.start_dir)
            except BadZipFile:
                # Not an archive: append one to whatever the file holds.
                fp.seek(0, os.SEEK_END)
                self._directory.start_dir = fp.tell()
                self._directory.modified = True

    def _load_directory(self, fp: IO[bytes]) -> None:
        self._directory.load(fp, self.metadata_encoding, self.debug, self.limits)

    # -- zipfile-compatible attributes, kept by the collaborators -------------

    @property
    def fp(self) -> IO[bytes] | None:
        """The underlying binary file object, or ``None`` once closed."""
        return self._stream.fp

    @property
    def filename(self) -> str | None:
        """The archive's path, or its file object's ``name``."""
        return self._stream.name

    @filename.setter
    def filename(self, name: str | None) -> None:
        self._stream.name = name

    @property
    def filelist(self) -> list[ZipInfo]:
        """Entries in central-directory order."""
        return self._directory.infos

    @property
    def NameToInfo(self) -> dict[str, ZipInfo]:  # noqa: N802  # the zipfile name
        """The last entry of each name."""
        return self._directory.by_name

    @property
    def start_dir(self) -> int:
        """Offset of the central directory (where the next entry goes)."""
        return self._directory.start_dir

    @start_dir.setter
    def start_dir(self, offset: int) -> None:
        self._directory.start_dir = offset

    @property
    def pwd(self) -> bytes | None:
        """The default password, or ``None``; see :meth:`setpassword`."""
        return self._encryption.password

    @pwd.setter
    def pwd(self, pwd: bytes | None) -> None:
        self.setpassword(pwd)

    @property
    def encryption(self) -> str | None:
        """Encryption for new entries (``WZ_AES``, ``ZIP_CRYPTO`` or ``None``)."""
        return self._encryption.method

    @encryption.setter
    def encryption(self, method: str | None) -> None:
        self._encryption.method = method

    def __enter__(self) -> Self:
        """Enter the runtime context and return this archive."""
        return self

    def __exit__(
        self,
        type: type[BaseException] | None,  # noqa: A002  # mirrors the __exit__ protocol
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit the runtime context and close the archive.

        Args:
            type: Exception type, if any.
            value: Exception value, if any.
            traceback: Exception traceback, if any.
        """
        self.close()

    @override
    def __repr__(self) -> str:
        """Return a developer-friendly string representation.

        Returns:
            A string of the form ``<module.ZipFile filename=... mode=...>``
            or ``<module.ZipFile [closed]>`` when the archive is closed.
        """
        result = [f"<{self.__class__.__module__}.{self.__class__.__qualname__}"]
        if self.fp is not None:
            if not self._stream.owned:
                result.append(f" file={self.fp!r}")
            elif self.filename is not None:
                result.append(f" filename={self.filename!r}")
            result.append(f" mode={self.mode!r}")
        else:
            result.append(" [closed]")
        result.append(">")
        return "".join(result)

    def namelist(self) -> list[str]:
        """Return a list of archive member names.

        Returns:
            A list of filenames in the order they appear in the central
            directory.
        """
        return [data.filename for data in self.filelist]

    def infolist(self) -> list[ZipInfo]:
        """Return a list of ZipInfo instances for all archive members.

        Returns:
            The internal :attr:`filelist` in central-directory order.
        """
        return self._directory.infos

    def inspect(
        self,
        path: StrPath | None = None,
        policy: ExtractPolicy | None = None,
    ) -> InspectionResult:
        """Inspect archive metadata without opening or processing payloads.

        No member data is read, decompressed, decrypted, or written.  Policy
        findings are returned in the report and never raise
        :class:`ExtractionError`.
        """
        effective_policy = policy or default_assessment_policy()
        return build_inspection_result(self.assess(path, effective_policy))

    def assess(
        self,
        path: StrPath | None = None,
        policy: ExtractPolicy | None = None,
    ) -> ArchiveAssessment:
        """Return the metadata assessment shared by policy consumers."""
        return assess_archive(self.filelist, path, policy)

    def printdir(self, file: IO[str] | None = None) -> None:
        """Print a formatted table of contents to *file*.

        Args:
            file: Output stream. Defaults to ``sys.stdout`` when ``None``.
        """
        print(f"{'File Name':<46} {'Modified    ':>19} {'Size':>12}", file=file)
        for zinfo in self.filelist:
            year, month, day, hour, minute, second = zinfo.date_time[:6]
            date = f"{year}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
            print(f"{zinfo.filename:<46} {date} {zinfo.file_size:>12}", file=file)

    def check_password(
        self,
        pwd: bytes | None = None,
        members: Iterable[str | ZipInfo] | None = None,
        *,
        full: bool = False,
    ) -> PasswordCheckResult:
        """Check whether *pwd* is the password of the encrypted members.

        By default only each member's password verifier is checked, so no
        payload is read or decompressed.  A rejection is definitive, but an
        acceptance only means the password is probably right: a wrong password
        still passes about 1 time in 256 for ZipCrypto and 1 in 65,536 for
        WinZip AES.  With ``full=True`` each member is also authenticated (the
        AES HMAC, or the CRC-32 for ZipCrypto), which is definitive but reads
        the member; a member whose data fails that check is reported as
        ``CORRUPT`` rather than ``REJECTED``.

        Args:
            pwd: Password to test. Defaults to :attr:`pwd`.
            members: Member names or infos to check. Defaults to all members.
            full: Authenticate each member's data as well.

        Returns:
            A :class:`~zipctl.zipfile.password.PasswordCheckResult`;
            unencrypted members are reported as ``UNENCRYPTED``.

        Raises:
            TypeError: If *pwd* is not ``bytes``.
            ValueError: If no non-empty password is available, or the archive
                is closed or being written.
        """
        if pwd is None:
            pwd = self.pwd
        require_bytes("pwd", pwd)
        if not pwd:
            raise ValueError("check_password() requires a non-empty password")
        self._stream.require_open("use")
        self._writer.ensure_idle("read from")

        infos = (
            self.filelist
            if members is None
            else [m if isinstance(m, ZipInfo) else self.getinfo(m) for m in members]
        )
        return PasswordCheckResult(
            tuple(
                MemberPasswordCheck(
                    info.filename,
                    check_member_password(
                        partial(self._reader.open, info, pwd), info, full=full
                    ),
                )
                for info in infos
            )
        )

    def testzip(self) -> str | None:
        """Verify each archive member by reading it and checking its CRC.

        Like the standard library's, only a corrupt member counts as bad: a
        member that cannot be opened at all (a missing or wrong password, an
        unsupported method) raises instead.

        Returns:
            The filename of the first bad entry, or ``None`` if all entries
            are intact.
        """
        chunk_size = 2**20
        for zinfo in self.filelist:
            try:
                with self.open(zinfo, "r") as f:
                    while f.read(chunk_size):
                        pass
            except BadZipFile:
                return zinfo.filename
        return None

    def getinfo(self, name: str) -> ZipInfo:
        """Return the ZipInfo for the archive member named *name*.

        Args:
            name: Archive member filename.

        Returns:
            The corresponding :class:`~zipctl.zipfile.info.ZipInfo`
            instance.

        Raises:
            KeyError: If no entry with the given name exists.
        """
        info = self.NameToInfo.get(name)
        if info is None:
            raise KeyError(f"There is no item named {name!r} in the archive")
        return info

    def setpassword(self, pwd: bytes | None) -> None:
        """Set the default decryption password for encrypted archive members.

        Args:
            pwd: Password bytes, or ``None`` to clear the stored password.

        Raises:
            TypeError: If *pwd* is not ``bytes`` or ``None``.
        """
        require_bytes("pwd", pwd or None)
        self._encryption.password = pwd or None

    def get_encryptor(
        self,
        encryption: str | None = None,
        password: bytes | None = None,
        *,
        nbits: int | None = None,
        force_wz_aes_version: int | None = None,
    ) -> BaseZipEncryptor:
        """Construct an encryptor, defaulting to this archive's settings.

        Args:
            encryption: Encryption scheme; defaults to :attr:`encryption`.
            password: Encryption password; defaults to :attr:`pwd`.
            nbits: AES key size in bits; defaults to the archive's setting.
            force_wz_aes_version: WinZip AES version override; defaults to the
                archive's setting.

        Returns:
            A :class:`~zipctl.cryptography.base.BaseZipEncryptor` for the
            selected scheme.

        Raises:
            PasswordRequired: If no password is available.
            ValueError: If the password is empty.
            NotImplementedError: If the encryption scheme is unknown.
        """
        return self._encryption.encryptor(
            encryption,
            password,
            nbits=nbits,
            force_wz_aes_version=force_wz_aes_version,
        )

    @property
    def comment(self) -> bytes:
        """The archive-level comment bytes."""
        return self._directory.comment

    @comment.setter
    def comment(self, comment: bytes) -> None:
        require_bytes("comment", comment)
        if len(comment) > ZIP_MAX_COMMENT:
            warnings.warn(
                f"Archive comment is too long; truncating to {ZIP_MAX_COMMENT} bytes",
                stacklevel=2,
            )
            comment = comment[:ZIP_MAX_COMMENT]
        self._directory.comment = comment
        self._directory.modified = True

    def read(self, name: str | ZipInfo, pwd: bytes | None = None) -> bytes:
        """Return the decompressed bytes for the archive member named *name*.

        Args:
            name: Member filename or a
                :class:`~zipctl.zipfile.info.ZipInfo` instance.
            pwd: Decryption password. Falls back to :attr:`pwd` when ``None``.

        Returns:
            Decompressed file contents as ``bytes``.
        """
        with self.open(name, "r", pwd) as fp:
            return fp.read()

    def open(
        self,
        name: str | ZipInfo,
        mode: ReadWriteMode = "r",
        pwd: bytes | None = None,
        *,
        force_zip64: bool = False,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
    ) -> IO[bytes]:
        """Open an archive member for reading or writing.

        Args:
            name: Member filename or a
                :class:`~zipctl.zipfile.info.ZipInfo` instance.
            mode: ``'r'`` to read an existing member, or ``'w'`` to write a
                new one.
            pwd: Decryption password for an encrypted member. Falls back to
                :attr:`pwd` when ``None``.
            force_zip64: When ``True``, always write local header size fields
                as ZIP64 regardless of file size.

        Returns:
            A binary file-like object. For ``mode='r'`` a
            :class:`~zipctl.zipfile.ext.ZipExtFile`; for ``mode='w'`` a
            :class:`~zipctl.zipfile.write.ZipWriteFile`.

        Raises:
            ValueError: If *mode* is invalid, *pwd* is supplied with
                ``mode='w'``, or the archive is closed.
            PasswordRequired: If the member is encrypted and no password is
                available.
            BadPassword: If the password does not match the member.
            NotImplementedError: If the member uses compressed patch data or
                strong encryption.
            BadZipFile: If the local file header is corrupt.
        """
        if mode not in {"r", "w"}:
            raise ValueError('open() requires mode "r" or "w"')
        if pwd and (mode == "w"):
            raise ValueError("pwd is only supported for reading files")
        self._stream.require_open("use")

        if isinstance(name, ZipInfo):
            zinfo = name
        elif mode == "w":
            zinfo = ZipInfo(name)
            zinfo.compress_type = self.compression
            zinfo.compress_level = self.compresslevel
        else:
            zinfo = self.getinfo(name)

        if mode == "w":
            return cast(  # pyright: ignore[reportInvalidCast]  # file-like, not an IO subclass
                IO[bytes],
                self._writer.open(
                    zinfo,
                    force_zip64=force_zip64,
                    encryption=encryption,
                    password=password,
                    extra=extra,
                ),
            )
        return cast(IO[bytes], self._reader.open(zinfo, pwd))  # pyright: ignore[reportInvalidCast]  # file-like, not an IO subclass

    def _copy_raw(
        self,
        source: ZipFile,
        info: ZipInfo,
        zinfo: ZipInfo,
        *,
        crc: int,
        size: int,
        pwd: bytes | None = None,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
    ) -> None:
        """Copy a member of *source* here without recompressing it.

        Private, but a contract for zipctl's own copy commands (``encrypt``,
        ``decrypt`` and ``rewrite``); see :meth:`ArchiveWriter.copy_raw`.
        """
        with source._reader.open(info, pwd) as reader:
            self._writer.copy_raw(
                reader,
                info,
                zinfo,
                crc=crc,
                size=size,
                encryption=encryption,
                password=password,
                extra=extra,
            )

    @overload
    def extract(
        self,
        member: str | ZipInfo,
        path: StrPath | None = None,
        pwd: bytes | PasswordProvider | None = None,
        *,
        policy: None = None,
        progress: ProgressCallback | None = None,
    ) -> str: ...

    @overload
    def extract(
        self,
        member: str | ZipInfo,
        path: StrPath | None = None,
        pwd: bytes | PasswordProvider | None = None,
        *,
        policy: ExtractPolicy,
        progress: ProgressCallback | None = None,
    ) -> ExtractMemberResult: ...

    def extract(
        self,
        member: str | ZipInfo,
        path: StrPath | None = None,
        pwd: bytes | PasswordProvider | None = None,
        *,
        policy: ExtractPolicy | None = None,
        progress: ProgressCallback | None = None,
    ) -> str | ExtractMemberResult:
        """Extract a single member to *path* on the filesystem.

        Args:
            member: Archive member filename or
                :class:`~zipctl.zipfile.info.ZipInfo` instance.
            path: Destination directory. Defaults to the current working
                directory when ``None``.
            pwd: Decryption password, or a callable given each encrypted
                member's :class:`~zipctl.zipfile.info.ZipInfo` that returns
                its password (or ``None``). ``None`` uses :attr:`pwd`.
            policy: Opt-in extraction policy; see :class:`ExtractPolicy`.
            progress: Callback receiving a :class:`ProgressEvent` as the
                member starts, as its data is written, and when it finishes.
                Raise from it to cancel; the exception propagates unchanged.

        Returns:
            The normalized path of the extracted file or directory.
        """
        if policy is not None:
            result = extract_members_with_policy(
                self, [member], path, pwd, policy, progress
            )
            if result.failed_count:
                raise ExtractionError(result)
            return result.members[0]

        path = os.fspath(os.getcwd() if path is None else path)
        if progress is None:
            return str(extract_member(self, member, path, pwd).target)
        return str(extract_all_with_progress(self, [member], path, pwd, progress)[0])

    @overload
    def extractall(
        self,
        path: StrPath | None = None,
        members: Iterable[str | ZipInfo] | None = None,
        pwd: bytes | PasswordProvider | None = None,
        *,
        policy: None = None,
        progress: ProgressCallback | None = None,
    ) -> None: ...

    @overload
    def extractall(
        self,
        path: StrPath | None = None,
        members: Iterable[str | ZipInfo] | None = None,
        pwd: bytes | PasswordProvider | None = None,
        *,
        policy: ExtractPolicy,
        progress: ProgressCallback | None = None,
    ) -> ExtractResult: ...

    def extractall(
        self,
        path: StrPath | None = None,
        members: Iterable[str | ZipInfo] | None = None,
        pwd: bytes | PasswordProvider | None = None,
        *,
        policy: ExtractPolicy | None = None,
        progress: ProgressCallback | None = None,
    ) -> None | ExtractResult:
        """Extract all (or a subset of) members to *path* on the filesystem.

        Args:
            path: Destination directory. Defaults to the current working
                directory when ``None``.
            members: Iterable of member names or
                :class:`~zipctl.zipfile.info.ZipInfo` instances to
                extract. Defaults to all members when ``None``.
            pwd: Decryption password, or a callable given each encrypted
                member's :class:`~zipctl.zipfile.info.ZipInfo` that returns
                its password (or ``None``). ``None`` uses :attr:`pwd`.
            policy: Opt-in extraction policy; see :class:`ExtractPolicy`.
            progress: Callback receiving a :class:`ProgressEvent` as each
                member starts, as its data is written, and when it finishes.
                Raise from it to cancel; members already extracted stay on
                disk, the member in flight leaves no partial file, and the
                exception propagates unchanged.  With a callback, *members* is
                resolved up front, so an unknown name raises ``KeyError``
                before anything is written.
        """
        if members is None:
            # Entries rather than names, so duplicate names keep their own data.
            members = list(self.filelist)
        if policy is not None:
            result = extract_members_with_policy(
                self, list(members), path, pwd, policy, progress
            )
            if result.failed_count:
                raise ExtractionError(result)
            return result
        path = os.fspath(os.getcwd() if path is None else path)
        if progress is not None:
            extract_all_with_progress(self, list(members), path, pwd, progress)
            return None
        for zipinfo in members:
            extract_member(self, zipinfo, path, pwd)
        return None

    def write(
        self,
        filename: StrPath,
        arcname: StrPath | None = None,
        compress_type: int | None = None,
        compresslevel: int | None = None,
        *,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
    ) -> None:
        """Add a file from the filesystem to the archive.

        Args:
            filename: Path to the source file or directory on disk.
            arcname: Name to use inside the archive. Defaults to *filename*
                with the drive and leading separators stripped.
            compress_type: Compression method for this entry. Overrides
                :attr:`compression` when provided.
            compresslevel: Compressor level for this entry. Overrides
                :attr:`compresslevel` when provided.

        Raises:
            ValueError: If the archive is closed or a write handle is open.
        """
        self._stream.require_open("write to")
        self._writer.ensure_idle("write to")

        zinfo = ZipInfo.from_file(
            filename, arcname, strict_timestamps=self._strict_timestamps
        )

        if zinfo.is_dir():
            zinfo.compress_size = 0
            zinfo.CRC = 0
            self.mkdir(zinfo)
        else:
            if compress_type is not None:
                zinfo.compress_type = compress_type
            else:
                zinfo.compress_type = self.compression

            if compresslevel is not None:
                zinfo.compress_level = compresslevel
            else:
                zinfo.compress_level = self.compresslevel

            with (
                open(
                    filename,
                    "rb",
                ) as src,
                self.open(
                    zinfo,
                    "w",
                    encryption=encryption,
                    password=password,
                    extra=extra,
                ) as dest,
            ):
                shutil.copyfileobj(src, dest)

    def writestr(
        self,
        zinfo_or_arcname: str | ZipInfo,
        data: str | bytes | bytearray,
        compress_type: int | None = None,
        compresslevel: int | None = None,
        *,
        encryption: EncryptionOverride = INHERIT_ENCRYPTION,
        password: bytes | None = None,
        extra: ZipFileExtra | None = None,
    ) -> None:
        """Write *data* into the archive under the given name or ZipInfo.

        Args:
            zinfo_or_arcname: Destination name inside the archive, or a
                pre-populated
                :class:`~zipctl.zipfile.info.ZipInfo` instance.
            data: File contents as a ``str`` (encoded to UTF-8) or
                ``bytes``/``bytearray``.
            compress_type: Compression method for this entry. Overrides the
                entry's own setting when provided.
            compresslevel: Compressor level for this entry. Overrides the
                entry's own setting when provided.

        Raises:
            ValueError: If the archive is closed or a write handle is open.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        if isinstance(zinfo_or_arcname, ZipInfo):
            zinfo = zinfo_or_arcname
        else:
            zinfo = ZipInfo(zinfo_or_arcname)._for_archive(self)  # pyright: ignore[reportPrivateUsage]  # the zipfile hook for writestr defaults

        self._stream.require_open("write to")
        self._writer.ensure_idle("write to")

        if compress_type is not None:
            zinfo.compress_type = compress_type

        if compresslevel is not None:
            zinfo.compress_level = compresslevel

        zinfo.file_size = len(data)
        with self._stream.lock:
            with self.open(
                zinfo,
                mode="w",
                encryption=encryption,
                password=password,
                extra=extra,
            ) as dest:
                dest.write(data)

    def mkdir(self, zinfo_or_directory_name: str | ZipInfo, mode: int = 511) -> None:
        """Add a directory entry to the archive.

        Args:
            zinfo_or_directory_name: Directory path (a trailing ``'/'`` is
                appended if absent) or a
                :class:`~zipctl.zipfile.info.ZipInfo` instance that
                describes a directory.
            mode: Unix permission bits for the directory entry. Defaults to
                ``0o777`` (octal 511).

        Raises:
            ValueError: If a :class:`~zipctl.zipfile.info.ZipInfo`
                instance is supplied that does not describe a directory.
            TypeError: If *zinfo_or_directory_name* is neither a ``str`` nor a
                :class:`~zipctl.zipfile.info.ZipInfo`.
        """
        if isinstance(zinfo_or_directory_name, ZipInfo):
            zinfo = zinfo_or_directory_name
            if not zinfo.is_dir():
                raise ValueError("The given ZipInfo does not describe a directory")
            zinfo.compress_size = 0
            zinfo.CRC = 0
            zinfo.file_size = 0
        elif isinstance(zinfo_or_directory_name, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            directory_name = zinfo_or_directory_name
            if not directory_name.endswith("/"):
                directory_name += "/"
            zinfo = ZipInfo(directory_name)
            zinfo.compress_size = 0
            zinfo.CRC = 0
            zinfo.external_attr = ((0o40000 | mode) & 0xFFFF) << 16
            zinfo.file_size = 0
            zinfo.external_attr |= 0x10
        else:
            raise TypeError("Expected type str or ZipInfo")  # pyright: ignore[reportUnreachable]

        zinfo.compress_type = ZIP_STORED
        with self.open(zinfo, "w", encryption=None):
            pass

    def __del__(self) -> None:
        """Ensure the archive is closed when the object is garbage-collected."""
        try:
            self.close()
        except Exception:
            pass

    def close(self) -> None:
        """Flush and close the archive.

        For writable modes (``'w'``, ``'x'``, ``'a'``), writes the central
        directory and end-of-central-directory record before closing the
        underlying file. The underlying file is only closed when it was opened
        by this instance (i.e. *file* was a path, not a file-like object).

        Raises:
            ValueError: If a write handle is still open on the archive.
        """
        with self._stream.lock:
            if self._stream.fp is None:
                return
            self._writer.ensure_idle("close")
            try:
                self._writer.finish()
            finally:
                self._reader.close()
                self._stream.close()
