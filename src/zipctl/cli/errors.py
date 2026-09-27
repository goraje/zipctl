"""Exit codes and the error type command handlers raise."""

from __future__ import annotations

from zipctl.cli.output import format_table

EXIT_OK = 0
EXIT_FAILURE = 1  # the operation ran and failed (bad member, violations, ...)
EXIT_USAGE = 2  # bad command line or bad configuration file
EXIT_BROKEN_PIPE = 141  # 128 + SIGPIPE: the reader of our output went away
EXIT_INTERRUPTED = 130  # 128 + SIGINT

EXIT_CODES = (
    (EXIT_OK, "success"),
    (EXIT_FAILURE, "the operation ran and failed (bad member, policy violations, ...)"),
    (
        EXIT_USAGE,
        "bad command line, bad configuration file or a pattern matching nothing",
    ),
    (EXIT_INTERRUPTED, "interrupted"),
    (EXIT_BROKEN_PIPE, "the reader of the output went away"),
)


def exit_codes_table() -> str:
    """The exit codes and their meaning, as printed by ``zipctl --exit-codes``."""
    rows = [[str(code), meaning] for code, meaning in EXIT_CODES]
    return "\n".join(format_table(["CODE", "MEANING"], rows))


class CliError(Exception):
    """A failure to report as ``zipctl: error: MESSAGE`` and exit with *code*."""

    def __init__(
        self, message: str, code: int = EXIT_FAILURE, details: tuple[str, ...] = ()
    ) -> None:
        super().__init__(message)
        self.message: str = message
        self.code: int = code
        self.details: tuple[str, ...] = details


class UsageError(CliError):
    """A bad command line or configuration: exit code :data:`EXIT_USAGE`."""

    def __init__(self, message: str, details: tuple[str, ...] = ()) -> None:
        super().__init__(message, EXIT_USAGE, details)


def os_error_text(exc: OSError) -> str:
    """The system's wording for *exc* (its message when it has no error code)."""
    return exc.strerror or str(exc)


def os_error_filename(exc: OSError) -> str | None:
    """The path *exc* is about, or ``None`` when it names none."""
    name: object = exc.filename  # pyright: ignore[reportAny]  # typeshed: Any
    return str(name) if name else None
