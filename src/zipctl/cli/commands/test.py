"""The ``test`` command."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from zipctl.cli.archive import open_archive
from zipctl.cli.commands.helpers.command import Subparsers, add_command
from zipctl.cli.commands.helpers.output_options import add_output_options
from zipctl.cli.commands.helpers.passwords import (
    PasswordArgs,
    PasswordFamily,
    PasswordPool,
    PasswordProblem,
    add_password_options,
)
from zipctl.cli.commands.helpers.progress import (
    ProgressArgs,
    ProgressRenderer,
    StepReporter,
    add_progress_option,
    progress_renderer,
)
from zipctl.cli.commands.helpers.selection import MEMBER_HELP, select_infos
from zipctl.cli.context import Context
from zipctl.cli.errors import EXIT_FAILURE, EXIT_OK
from zipctl.cli.output import (
    count,
    printable,
)
from zipctl.cli.reports import VerifyReport
from zipctl.exceptions import BadZipFile
from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.shared import CHUNK


class TestArgs(PasswordArgs, ProgressArgs, Protocol):
    archive: str
    members: list[str]


@dataclass(frozen=True)
class Tested:
    """The outcome for one member; *detail* says what is wrong when it is not *ok*."""

    name: str
    ok: bool
    detail: str | None = None

    @property
    def status(self) -> str:
        return "ok" if self.ok else "failed"


def _test_member(zf: ZipFile, info: ZipInfo, pool: PasswordPool) -> Tested:
    """Read *info* to its end."""
    try:
        password = None
        if info.is_encrypted:
            resolved = pool.resolve(zf, info)
            if isinstance(resolved, PasswordProblem):
                return Tested(info.filename, False, pool.explain(resolved))
            password = resolved
        with zf.open(info, pwd=password) as stream:
            while stream.read(CHUNK):
                pass
    except Exception as exc:  # any failure to read a member means it is bad
        return Tested(info.filename, False, _read_error_text(exc, info))
    return Tested(info.filename, True)


def _read_error_text(exc: Exception, info: ZipInfo) -> str:
    text = str(exc) or type(exc).__name__
    if isinstance(exc, BadZipFile) and info.is_encrypted:
        return f"{text} (corrupt data, or the password is wrong)"
    if isinstance(exc, (NotImplementedError, RuntimeError)):
        return f"unsupported: {text}"
    if isinstance(exc, BadZipFile):
        return text
    return f"{type(exc).__name__}: {text}"


def _test_members(
    zf: ZipFile,
    infos: list[ZipInfo],
    pool: PasswordPool,
    renderer: ProgressRenderer | None,
) -> list[Tested]:
    steps = StepReporter(renderer, ((i.filename, i.file_size) for i in infos))
    results: list[Tested] = []
    for index, info in enumerate(infos):
        steps.start(index)
        result = _test_member(zf, info, pool)
        results.append(result)
        steps.finish(index, ok=result.ok)
    return results


def cmd_test(args: TestArgs, ctx: Context) -> int:
    with progress_renderer(ctx.output, args.progress) as renderer:
        with open_archive(args.archive, ctx) as zf:
            pool = PasswordFamily.from_args(args).pool(ctx)
            infos = select_infos(zf.infolist(), args.members)
            results = _test_members(zf, infos, pool, renderer)

    failed = [result for result in results if not result.ok]
    output = ctx.output
    if output.json:
        report: VerifyReport = {
            "ok": not failed,
            "archive": args.archive,
            "tested": len(results),
            "failed": len(failed),
            "members": [
                {"name": r.name, "status": r.status, "detail": r.detail}
                for r in results
            ],
        }
        output.document(report)
        return EXIT_FAILURE if failed else EXIT_OK
    for result in results:
        if not result.ok:
            name, detail = printable(result.name), printable(result.detail or "")
            output.problem(f"FAILED  {name}: {detail}")
        else:
            output.detail(f"OK      {printable(result.name)}")
    tested = f"Tested {count(len(results), 'member')}"
    if failed:
        output.summary(f"{tested}: {len(failed)} failed", failed=True)
    else:
        output.summary(f"{tested}: all OK")
    return EXIT_FAILURE if failed else EXIT_OK


def register(subparsers: Subparsers) -> None:
    parser = add_command(
        subparsers, "test", cmd_test, "read every member and check its integrity"
    )
    parser.add_argument("archive", metavar="ARCHIVE", help="the archive to test")
    parser.add_argument("members", nargs="*", metavar="MEMBER", help=MEMBER_HELP)
    add_progress_option(parser)
    add_output_options(parser, verbose_help="also list members that pass", quiet=True)
    add_password_options(parser)
