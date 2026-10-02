"""The report the copy commands print after a copy."""

from __future__ import annotations

from zipctl.cli.commands.helpers.copy_options import CopyJob
from zipctl.cli.commands.helpers.copy_targets import Copied
from zipctl.cli.context import Context
from zipctl.cli.output import JsonValue, count, printable, write_json


def report_copy(ctx: Context, job: CopyJob, verb: str, copied: list[Copied]) -> None:
    files = [c for c in copied if not c.directory]
    encrypted = sum(c.after.is_encrypted for c in files)
    if job.report.json:
        members: list[dict[str, JsonValue]] = [
            {
                "name": c.name,
                "directory": c.directory,
                "size": c.size,
                "compression": c.compression,
                "encryption_before": c.before.label,
                "encryption_after": c.after.label,
            }
            for c in copied
        ]
        write_json(
            ctx.stdout,
            {
                "ok": True,
                "input": job.input,
                "output": job.output,
                "verified": job.verify,
                "file_count": len(files),
                "directory_count": len(copied) - len(files),
                "encrypted_count": encrypted,
                "members": members,
            },
        )
        return
    if job.report.quiet:
        return
    if job.report.verbose:
        for c in copied:
            if c.directory:
                ctx.out(f"Copying: {printable(c.name)} (directory)")
                continue
            change = c.after.label
            if c.before != c.after:
                change = f"{c.before.label} -> {change}"
            ctx.out(f"Copying: {printable(c.name)} ({c.compression}, {change})")
    if ctx.warned or (job.report.verbose and copied):
        ctx.out()
    parts = [
        count(len(files), "file"),
        count(len(copied) - len(files), "directory", "directories"),
    ]
    if encrypted:
        parts.append(f"{encrypted} encrypted")
    verified = " (verified)" if job.verify else ""
    ctx.out(
        f"{verb} {printable(job.input)} into {printable(job.output)}: "
        f"{', '.join(parts)}{verified}"
    )
