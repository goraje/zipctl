"""Turning the paths given to ``create`` into the entries to add."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from ziplet.cli.commands.helpers.selection import glob_matcher
from ziplet.cli.errors import CliError, os_error_filename, os_error_text
from ziplet.cli.output import printable

__all__ = ["Collector", "Entry"]


@dataclass(frozen=True)
class Entry:
    """One thing to add: the file on disk and its name in the archive."""

    source: str
    arcname: str
    is_dir: bool
    link_target: str | None = None  # set for a symbolic link stored as a link


def _arcname(given: str) -> str:
    """The archive name for command-line *given*, or refuse one that escapes."""
    path = os.path.splitdrive(os.path.normpath(given))[1].lstrip("/\\")
    if path == ".":
        return ""
    if path == ".." or path.startswith(("../", "..\\")):
        raise CliError(
            f"{printable(given)}: outside the current directory, so it cannot be "
            "stored under a safe name (use -C DIR to choose the base directory)"
        )
    return path.replace(os.sep, "/")


def _stored_name(name: str) -> str:
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        raise CliError(
            f"cannot store {printable(name)}: the file name is not valid UTF-8"
        ) from None
    return name


def _unreadable(exc: OSError) -> None:
    """``os.walk`` would skip a directory it cannot list; a backup must not."""
    where = printable(os_error_filename(exc) or "")
    raise CliError(f"cannot read {where}: {os_error_text(exc)}") from None


def _join(prefix: str, name: str) -> str:
    return f"{prefix}/{name}".lstrip("/")


def _not_a_file(path: str) -> str | None:
    """Why *path* cannot be added as a file, or ``None`` when it is a regular one."""
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        broken = isinstance(exc, FileNotFoundError) and os.path.islink(path)
        return "broken symbolic link" if broken else os_error_text(exc)
    return None if stat.S_ISREG(mode) else "not a regular file"


class Collector:
    """Walks the command-line paths and lists what to add, and what was skipped."""

    def __init__(
        self,
        base: str | None,
        archive: str,
        exclude: Sequence[str] = (),
        symlinks: str = "follow",
    ) -> None:
        """*symlinks* is ``follow``, ``store`` or ``skip`` (see ``--symlinks``)."""
        self.base: str | None = base
        self.symlinks: str = symlinks
        try:
            self._archive_stat: os.stat_result | None = os.stat(archive)
        except OSError:  # not written yet, so nothing collected can be it
            self._archive_stat = None
        self.entries: list[Entry] = []
        self.skipped: list[tuple[str, str]] = []
        self._seen: set[str] = set()
        self._exclude: list[tuple[str, Callable[[str], bool]]] = [
            (p, glob_matcher(p.rstrip("/") or p)) for p in exclude
        ]
        self._used: set[str] = set()

    def unused_excludes(self) -> list[str]:
        """The ``--exclude`` patterns that matched nothing (likely typos)."""
        return [p for p, _ in self._exclude if p not in self._used]

    def _excluded(self, arcname: str, is_dir: bool) -> bool:
        """Whether an exclude pattern names *arcname*.

        A pattern with a ``/`` in it is matched against the whole archive name;
        one without is matched against the last name only, at any depth.  A
        directory is also matched as ``name/``, so ``build/**`` leaves out
        ``build`` itself, as ``zip -x`` and ``tar --exclude`` do.
        """
        name = arcname.rstrip("/")
        last = name.rsplit("/", 1)[-1]
        excluded = False
        for pattern, matches in self._exclude:
            if "/" in pattern.rstrip("/"):
                hit = matches(name) or (is_dir and matches(name + "/"))
            else:
                hit = matches(last)
            if hit:
                self._used.add(pattern)
                excluded = True
        return excluded

    def _is_archive(self, source: str) -> bool:
        if self._archive_stat is None:
            return False
        try:
            return os.path.samestat(self._archive_stat, os.stat(source))
        except OSError:  # vanished or unreadable: reported when it is added
            return False

    def _add(
        self,
        source: str,
        arcname: str,
        is_dir: bool,
        link_target: str | None = None,
    ) -> None:
        if link_target is None and self._is_archive(source):
            self.skipped.append((source, "it is the archive being written"))
            return
        key = arcname + "/" if is_dir else arcname
        if key in self._seen:
            return
        self._seen.add(key)
        self.entries.append(Entry(source, _stored_name(key), is_dir, link_target))

    def _link(self, source: str, arcname: str) -> None:
        """Handle the symbolic link *source* per ``--symlinks`` (not ``follow``)."""
        if self.symlinks == "skip":
            self._skip(source, "symbolic link")
            return
        target = os.readlink(source)
        try:
            target.encode("utf-8")
        except UnicodeEncodeError:
            raise CliError(
                f"cannot store the link {printable(source)}: its target is not "
                "valid UTF-8"
            ) from None
        self._add(source, arcname, False, target)

    def _skip(self, source: str, reason: str) -> None:
        self.skipped.append((os.path.normpath(source), reason))

    def add_path(self, given: str) -> None:
        """Add a path named on the command line; one that cannot be read is fatal."""
        source = (
            given
            if os.path.isabs(given) or not self.base
            else os.path.join(self.base, given)
        )
        arc = _arcname(given)
        if arc and self._excluded(arc, os.path.isdir(source)):
            return
        if self.symlinks != "follow" and os.path.islink(source):
            self._link(source, arc or os.path.basename(source))
            return
        try:
            mode = os.stat(source).st_mode
        except OSError as exc:
            raise CliError(
                f"cannot read {printable(given)}: {os_error_text(exc)}"
            ) from None
        if stat.S_ISDIR(mode):
            self._walk(source, arc)
        elif stat.S_ISREG(mode):
            self._add(source, arc or os.path.basename(source), False)
        else:
            raise CliError(f"{printable(given)}: not a regular file or directory")

    def _walk(self, top: str, arc: str) -> None:
        """Add what is under *top*; what cannot be read is skipped with a reason."""
        if arc:
            self._add(top, arc, True)
        for root, dirs, files in os.walk(top, onerror=_unreadable):
            dirs.sort()
            files.sort()
            here = os.path.relpath(root, top)
            prefix = arc if here == "." else f"{arc}/{here}".lstrip("/")
            prefix = prefix.replace(os.sep, "/")
            self._walk_dirs(root, dirs, prefix)
            for name in files:
                path = os.path.join(root, name)
                arcname = _join(prefix, name)
                if self._excluded(arcname, False):
                    continue
                if self.symlinks != "follow" and os.path.islink(path):
                    self._link(path, arcname)
                elif reason := _not_a_file(path):
                    self._skip(path, reason)
                else:
                    self._add(path, arcname, False)

    def _walk_dirs(self, root: str, dirs: list[str], prefix: str) -> None:
        """Add the directories of one level; *dirs* keeps those to descend into."""
        for name in list(dirs):
            path = os.path.join(root, name)
            arcname = _join(prefix, name)
            if self._excluded(arcname, True):
                dirs.remove(name)
            elif os.path.islink(path):
                dirs.remove(name)
                if self.symlinks == "store":
                    self._link(path, arcname)
                else:
                    self._skip(path, "symbolic link to a directory")
            else:
                self._add(path, arcname, True)
