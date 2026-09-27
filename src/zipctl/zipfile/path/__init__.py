"""A :mod:`pathlib`-style interface for ZIP archives.

:class:`Path` mirrors CPython 3.14's ``zipfile.Path``: it accepts either an
already-open :class:`~zipctl.zipfile.file.ZipFile` or an archive filename, and
lets callers navigate, read, and glob archive members using familiar
``pathlib.Path``-like semantics, including implied (unlisted) directory
entries.

Adapted from CPython's ``zipfile._path`` package.
"""

# Friend access inside the zipfile package (ruff exempts it via SLF001).
# pyright: reportPrivateUsage=false

from __future__ import annotations

import contextlib
import io
import itertools
import pathlib
import posixpath
import re
from collections.abc import Iterable, Iterator
from typing import IO, Literal, cast, overload

from typing_extensions import override

from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.path.glob import Translator
from zipctl.zipfile.shared import ReadWriteMode, StrPath

__all__ = ["Path"]


def _parents(path: str) -> Iterator[str]:
    """Generate all parent segments of *path* (excluding *path* itself).

    >>> list(_parents('b/d'))
    ['b']
    >>> list(_parents('/b/d/'))
    ['/b']
    >>> list(_parents('b/d/f/'))
    ['b/d', 'b']
    >>> list(_parents('b'))
    []
    >>> list(_parents(''))
    []
    """
    return itertools.islice(_ancestry(path), 1, None)


def _ancestry(path: str) -> Iterator[str]:
    """Generate all ancestor segments of *path*, including *path* itself.

    >>> list(_ancestry('b/d'))
    ['b/d', 'b']
    >>> list(_ancestry('/b/d/'))
    ['/b/d', '/b']
    >>> list(_ancestry('b/d/f/'))
    ['b/d/f', 'b/d', 'b']
    >>> list(_ancestry('b'))
    ['b']
    >>> list(_ancestry(''))
    []

    Multiple separators are treated like a single one.

    >>> list(_ancestry('//b//d///f//'))
    ['//b//d///f', '//b//d', '//b']
    """
    path = path.rstrip(posixpath.sep)
    while path.rstrip(posixpath.sep):
        yield path
        path, _tail = posixpath.split(path)


def _dedupe(iterable: Iterable[str]) -> Iterable[str]:
    """Deduplicate *iterable*, preserving original order."""
    return dict.fromkeys(iterable)


def _difference(minuend: Iterable[str], subtrahend: Iterable[str]) -> Iterator[str]:
    """Yield items from *minuend* that are not present in *subtrahend*.

    Retains order with O(1) membership lookup.
    """
    return itertools.filterfalse(set(subtrahend).__contains__, minuend)


class CompleteDirs(ZipFile):
    """A :class:`~zipctl.zipfile.file.ZipFile` that always lists implied dirs.

    ZIP archives frequently omit explicit directory entries; a member such as
    ``foo/bar.txt`` implies a ``foo/`` directory even when no entry for
    ``foo/`` exists in the archive. :class:`CompleteDirs` synthesizes those
    implied directory names so :class:`Path` navigation and iteration behave
    consistently regardless of whether directory entries were written.

    >>> list(CompleteDirs._implied_dirs(['foo/bar.txt', 'foo/bar/baz.txt']))
    ['foo/', 'foo/bar/']
    >>> list(CompleteDirs._implied_dirs(['foo/bar.txt', 'foo/bar/baz.txt', 'foo/bar/']))
    ['foo/']
    """

    @staticmethod
    def _implied_dirs(names: Iterable[str]) -> Iterable[str]:
        parents = itertools.chain.from_iterable(map(_parents, names))
        as_dirs = (p + posixpath.sep for p in parents)
        return _dedupe(_difference(as_dirs, names))

    @override
    def namelist(self) -> list[str]:
        """Return archive member names, including synthesized implied dirs."""
        names = super().namelist()
        return names + list(self._implied_dirs(names))

    def _name_set(self) -> set[str]:
        return set(self.namelist())

    def resolve_dir(self, name: str) -> str:
        """Return *name* with a trailing slash if it names an implied directory."""
        names = self._name_set()
        dirname = name + "/"
        dir_match = name not in names and dirname in names
        return dirname if dir_match else name

    @override
    def getinfo(self, name: str) -> ZipInfo:
        """Return :class:`ZipInfo` for *name*, synthesizing implied dirs."""
        try:
            return super().getinfo(name)
        except KeyError:
            if not name.endswith("/") or name not in self._name_set():
                raise
            return ZipInfo(filename=name)

    @classmethod
    def make(cls, source: ZipFile | StrPath) -> CompleteDirs:
        """Return a :class:`CompleteDirs`-compatible wrapper around *source*.

        If *source* is already a :class:`CompleteDirs`, it is returned
        unchanged. If it is some other :class:`~zipctl.zipfile.file.ZipFile`
        instance, its ``__class__`` is mutated in place to a
        :class:`CompleteDirs` subclass (this project has no ``__slots__`` on
        :class:`~zipctl.zipfile.file.ZipFile`, so the mutation is safe).
        Otherwise, *source* is treated as an archive filename and opened for
        reading.
        """
        if isinstance(source, CompleteDirs):
            return source

        if not isinstance(source, ZipFile):
            return cls(source)

        # Only allow FastLookup when the supplied ZipFile is read-only.
        target_cls: type[CompleteDirs] = cls
        if "r" not in source.mode:
            target_cls = CompleteDirs

        source.__class__ = target_cls
        return cast(CompleteDirs, source)

    @classmethod
    def inject(cls, zf: ZipFile) -> ZipFile:
        """Write directory entries for any directories implied by *zf*."""
        for name in cls._implied_dirs(zf.namelist()):
            zf.writestr(name, b"")
        return zf


class FastLookup(CompleteDirs):
    """A :class:`CompleteDirs` variant that caches name lookups.

    Only safe to use for read-only archives, where the member list cannot
    change out from under the cache.
    """

    # Filled on first use; a missing attribute means "not cached yet".
    __names: list[str]  # pyright: ignore[reportUninitializedInstanceVariable]
    __lookup: set[str]  # pyright: ignore[reportUninitializedInstanceVariable]

    @override
    def namelist(self) -> list[str]:
        with contextlib.suppress(AttributeError):
            return self.__names
        self.__names = super().namelist()
        return self.__names

    @override
    def _name_set(self) -> set[str]:
        with contextlib.suppress(AttributeError):
            return self.__lookup
        self.__lookup = super()._name_set()
        return self.__lookup


class Path:
    """A :mod:`pathlib`-style interface for navigating a ZIP archive.

    Consider a zip file with this structure::

        .
        ├── a.txt
        └── b
            ├── c.txt
            └── d
                └── e.txt

    >>> import io
    >>> data = io.BytesIO()
    >>> zf = ZipFile(data, 'w')
    >>> zf.writestr('a.txt', 'content of a')
    >>> zf.writestr('b/c.txt', 'content of c')
    >>> zf.writestr('b/d/e.txt', 'content of e')
    >>> zf.filename = 'mem/abcde.zip'

    ``Path`` accepts the ``ZipFile`` object itself or a filename.

    >>> path = Path(zf)

    From there, several path operations are available.

    Directory iteration (excluding the zip file itself):

    >>> a, b = path.iterdir()
    >>> a
    Path('mem/abcde.zip', 'a.txt')
    >>> b
    Path('mem/abcde.zip', 'b/')

    ``name`` property:

    >>> b.name
    'b'

    Join with the divide operator:

    >>> c = b / 'c.txt'
    >>> c
    Path('mem/abcde.zip', 'b/c.txt')
    >>> c.name
    'c.txt'

    Read text:

    >>> c.read_text(encoding='utf-8')
    'content of c'

    Existence:

    >>> c.exists()
    True
    >>> (b / 'missing.txt').exists()
    False

    Coercion to string:

    >>> str(c)
    'mem/abcde.zip/b/c.txt'

    At the root, ``name``, ``filename``, and ``parent`` resolve to the
    zipfile.

    >>> str(path)
    'mem/abcde.zip/'
    >>> path.name
    'abcde.zip'
    >>> path.filename == pathlib.Path('mem/abcde.zip')
    True
    >>> str(path.parent)
    'mem'
    """

    __repr_format = "{self.__class__.__name__}({self.root.filename!r}, {self.at!r})"

    root: CompleteDirs
    at: str

    def __init__(self, root: ZipFile | StrPath, at: str = "") -> None:
        """Construct a :class:`Path` from a :class:`ZipFile` or filename.

        Note: when *root* is an existing :class:`~zipctl.zipfile.file.ZipFile`
        instance, its ``__class__`` is mutated to a specialized subclass. If
        the caller needs to retain the original type, pass a filename or a
        separate :class:`~zipctl.zipfile.file.ZipFile` instance instead.

        Args:
            root: An open archive, or a path to one.
            at: The archive-relative POSIX path this :class:`Path` refers to.
                Empty string refers to the archive root.
        """
        self.root = FastLookup.make(root)
        self.at = at

    @override
    def __eq__(self, other: object) -> bool:
        """Return whether *other* is a :class:`Path` for the same root and location."""
        if self.__class__ is not other.__class__:
            return NotImplemented
        assert isinstance(other, Path)
        return (self.root, self.at) == (other.root, other.at)

    @override
    def __hash__(self) -> int:
        """Return a hash consistent with :meth:`__eq__`."""
        return hash((self.root, self.at))

    @overload
    def open(
        self,
        mode: Literal["r", "w"] = "r",
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
        line_buffering: bool = False,
        write_through: bool = False,
        *,
        pwd: bytes | None = None,
    ) -> io.TextIOWrapper: ...

    @overload
    def open(
        self, mode: Literal["rb", "wb"], *, pwd: bytes | None = None
    ) -> IO[bytes]: ...

    def open(
        self,
        mode: str = "r",
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
        line_buffering: bool = False,
        write_through: bool = False,
        *,
        pwd: bytes | None = None,
    ) -> io.TextIOWrapper | IO[bytes]:
        """Open this entry for reading or writing.

        Follows the semantics of :meth:`pathlib.Path.open`: the text mode
        arguments are passed through to :class:`io.TextIOWrapper`.

        Args:
            mode: Any of ``'r'``, ``'rb'``, ``'w'``, ``'wb'``.
            encoding: Text encoding; only valid in text mode.
            errors: Text error handling; only valid in text mode.
            newline: Text newline handling; only valid in text mode.
            line_buffering: Flush on newline; only valid in text mode.
            write_through: Write straight through; only valid in text mode.
            pwd: Decryption password for reading an encrypted member. Falls
                back to the archive's default password (set via
                :meth:`~zipctl.zipfile.file.ZipFile.setpassword`) when
                ``None``.

        Raises:
            IsADirectoryError: If this path names a directory.
            FileNotFoundError: If reading and this path does not exist.
            ValueError: If binary mode is combined with text-mode arguments.
        """
        if self.is_dir():
            raise IsADirectoryError(self)
        zip_mode = cast(ReadWriteMode, mode[0])
        if zip_mode == "r" and not self.exists():
            raise FileNotFoundError(self)
        stream = self.root.open(self.at, zip_mode, pwd)
        if "b" in mode:
            if (
                encoding is not None
                or errors is not None
                or newline is not None
                or line_buffering
                or write_through
            ):
                raise ValueError("encoding args invalid for binary operation")
            return stream
        return io.TextIOWrapper(
            stream, encoding, errors, newline, line_buffering, write_through
        )

    def _base(self) -> pathlib.PurePosixPath | pathlib.Path:
        return pathlib.PurePosixPath(self.at) if self.at else self.filename

    @property
    def name(self) -> str:
        """The final path component, or the archive's own filename at the root."""
        return self._base().name

    @property
    def suffix(self) -> str:
        """The final component's last suffix, if any."""
        return self._base().suffix

    @property
    def suffixes(self) -> list[str]:
        """A list of the final component's suffixes."""
        return self._base().suffixes

    @property
    def stem(self) -> str:
        """The final path component, without its suffix."""
        return self._base().stem

    @property
    def filename(self) -> pathlib.Path:
        """The archive filename joined with this path's archive-relative location.

        Raises:
            TypeError: If the underlying archive has no filename (for
                example, an in-memory buffer).
        """
        if self.root.filename is None:
            raise TypeError("root.filename is not set")
        return pathlib.Path(self.root.filename).joinpath(self.at)

    def read_text(
        self,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
        line_buffering: bool = False,
        write_through: bool = False,
    ) -> str:
        """Return this member's contents decoded as text."""
        with self.open(
            "r", encoding, errors, newline, line_buffering, write_through
        ) as strm:
            return strm.read()

    def read_bytes(self) -> bytes:
        """Return this member's raw, decompressed contents."""
        with self.open("rb") as strm:
            return strm.read()

    def _is_child(self, path: Path) -> bool:
        return posixpath.dirname(path.at.rstrip("/")) == self.at.rstrip("/")

    def _next(self, at: str) -> Path:
        return self.__class__(self.root, at)

    def is_dir(self) -> bool:
        """Return whether this path names a directory (including the archive root)."""
        return not self.at or self.at.endswith("/")

    def is_file(self) -> bool:
        """Return whether this path names a file that exists in the archive."""
        return self.exists() and not self.is_dir()

    def exists(self) -> bool:
        """Return whether this path names an entry present in the archive."""
        return self.at in self.root._name_set()

    def iterdir(self) -> Iterator[Path]:
        """Iterate over the direct children of this directory.

        Raises:
            ValueError: If this path does not name a directory.
        """
        if not self.is_dir():
            raise ValueError("Can't listdir a file")
        subs = map(self._next, self.root.namelist())
        return filter(self._is_child, subs)

    def match(self, path_pattern: str) -> bool:
        """Return whether this path matches *path_pattern*."""
        return pathlib.PurePosixPath(self.at).match(path_pattern)

    def is_symlink(self) -> bool:
        """Return whether this path is a symlink."""
        if not self.exists():
            return False
        return self.root.getinfo(self.at).is_symlink()

    def glob(self, pattern: str) -> Iterator[Path]:
        """Yield paths matching the glob *pattern*, relative to this directory.

        Raises:
            ValueError: If *pattern* is empty, or ``**`` appears anywhere
                other than as a full path segment.
        """
        if not pattern:
            raise ValueError(f"Unacceptable pattern: {pattern!r}")

        prefix = re.escape(self.at)
        translator = Translator(seps="/")
        matches = re.compile(prefix + translator.translate(pattern)).fullmatch
        return map(self._next, filter(matches, self.root.namelist()))

    def rglob(self, pattern: str) -> Iterator[Path]:
        """Yield paths matching *pattern* at any depth under this directory."""
        return self.glob(f"**/{pattern}")

    def relative_to(self, other: Path, *extra: str) -> str:
        """Return this path's location relative to *other*."""
        return posixpath.relpath(str(self), str(other.joinpath(*extra)))

    @override
    def __str__(self) -> str:
        """Return the archive filename joined with this path."""
        return posixpath.join(str(self.root.filename), self.at)

    @override
    def __repr__(self) -> str:
        """Return an unambiguous representation showing the archive and location."""
        return f"{self.__class__.__name__}({self.root.filename!r}, {self.at!r})"

    def joinpath(self, *other: str) -> Path:
        """Return a new :class:`Path` joined with each of *other*."""
        next_at = posixpath.join(self.at, *other)
        return self._next(self.root.resolve_dir(next_at))

    def __truediv__(self, other: str) -> Path:
        return self.joinpath(other)

    @property
    def parent(self) -> Path:
        """Return the containing directory."""
        if not self.at:
            # At the root this is the archive's own pathlib parent, as in zipfile.Path.
            return cast(Path, self.filename.parent)  # pyright: ignore[reportInvalidCast]
        parent_at = posixpath.dirname(self.at.rstrip("/"))
        if parent_at:
            parent_at += "/"
        return self._next(parent_at)
