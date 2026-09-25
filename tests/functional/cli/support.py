"""Helpers for the CLI functional tests: run the real CLI, build archives."""

from __future__ import annotations

import io
import os
import struct
import subprocess
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import ziplet
from ziplet import ZipFile
from ziplet.zipfile.info import ZipInfo

if sys.platform != "win32":
    import pty
    import select
    import signal

HAS_PTY = sys.platform != "win32"


def _default_sigint() -> None:
    """Undo an ignored SIGINT inherited from a background parent (`cmd &`).

    Python leaves KeyboardInterrupt off when it starts with SIGINT ignored, so
    the Ctrl-C tests would hang whenever the suite itself runs in the background.
    """
    signal.signal(signal.SIGINT, signal.SIG_DFL)


PASSWORD = "correct horse battery"
TIMEOUT = 60
TERMINAL_TIMEOUT = 20
END_OF_INPUT = "\x04"  # Ctrl-D, typed alone at a prompt


@dataclass(frozen=True)
class Result:
    """What one run of the CLI produced."""

    returncode: int
    stdout: str
    stderr: str

    def __str__(self) -> str:
        return (
            f"exit={self.returncode}\n--- stdout ---\n{self.stdout}"
            f"--- stderr ---\n{self.stderr}"
        )


def clean_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """A predictable environment: UTF-8 I/O, no inherited ziplet password."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("ZIPLET_")}
    env["PYTHONIOENCODING"] = "utf-8"
    env.pop("PYTHONWARNINGS", None)
    if extra:
        env.update(extra)
    return env


def command(*args: str) -> list[str]:
    return [sys.executable, "-m", "ziplet", *args]


def run(
    *args: str,
    stdin: str | bytes | None = None,
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> Result:
    """Run ``python -m ziplet ARGS`` and capture everything it did."""
    completed = subprocess.run(
        command(*args),
        input=stdin if isinstance(stdin, bytes) else (stdin or "").encode(),
        capture_output=True,
        env=clean_env(env),
        cwd=cwd,
        timeout=TIMEOUT,
    )
    return Result(
        completed.returncode,
        completed.stdout.decode("utf-8"),
        completed.stderr.decode("utf-8"),
    )


def run_in_terminal(
    *args: str,
    replies: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
    interrupt_at_prompt: int | None = None,
    cwd: Path | None = None,
) -> tuple[Result, int]:
    """Run the CLI with standard input attached to a pseudo-terminal.

    Each entry of *replies* is typed (plus Enter) when the next password
    prompt appears.  The child has no controlling terminal, so getpass uses
    standard input and writes the prompt (and any echo mask) to standard error.
    With *interrupt_at_prompt*, SIGINT is sent when that prompt (1-based) shows.
    Returns the result and the number of prompts seen.
    """
    assert HAS_PTY
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        command(*args),
        stdin=slave,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=clean_env(env),
        cwd=cwd,
        start_new_session=True,
        preexec_fn=_default_sigint,
    )
    os.close(slave)
    assert proc.stderr is not None
    stderr_fd = proc.stderr.fileno()
    seen = b""
    answered = 0
    deadline = time.monotonic() + TERMINAL_TIMEOUT
    try:
        while True:
            if time.monotonic() > deadline:
                proc.kill()
                raise AssertionError(
                    f"terminal run timed out after answering {answered} prompts;"
                    f" stderr so far: {seen!r}"
                )
            ready, _, _ = select.select([stderr_fd], [], [], 0.05)
            if ready:
                chunk = os.read(stderr_fd, 4096)
                if not chunk:
                    break
                seen += chunk
            if _prompts_seen(seen) > answered and _prompt_is_complete(seen):
                answered += 1
                if interrupt_at_prompt == answered:
                    proc.send_signal(signal.SIGINT)
                elif answered <= len(replies):
                    reply = replies[answered - 1]
                    end = b"" if reply == END_OF_INPUT else b"\n"
                    os.write(master, reply.encode() + end)
                else:
                    os.write(master, b"\n")
            if proc.poll() is not None and not ready:
                break
        stdout, rest = proc.communicate(timeout=TERMINAL_TIMEOUT)
    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(master)
    seen += rest
    return (
        Result(proc.returncode, stdout.decode("utf-8"), seen.decode("utf-8")),
        answered,
    )


_PROMPT_STARTS = (b"Password for ", b"Password: ", b"Confirm password")


def _prompts_seen(seen: bytes) -> int:
    return sum(seen.count(start) for start in _PROMPT_STARTS)


def _prompt_is_complete(seen: bytes) -> bool:
    """True when the last prompt has been fully written (ends with ': ')."""
    start = max(seen.rfind(marker) for marker in _PROMPT_STARTS)
    tail = seen[start:]
    return b": " in tail and b"\n" not in tail.split(b": ", 1)[1]


# --- archives ---------------------------------------------------------------


def write_archive(
    path: Path,
    members: Iterable[tuple[str | ZipInfo, bytes]],
    *,
    compression: int = ziplet.ZIP_STORED,
    encryption: str | None = None,
    password: bytes | None = None,
    extra: ziplet.ZipFileExtra | None = None,
    comment: bytes = b"",
) -> Path:
    with ZipFile(
        path, "w", compression=compression, encryption=encryption, extra=extra
    ) as zf:
        if password is not None:
            zf.setpassword(password)
        if comment:
            zf.comment = comment
        for name, data in members:
            zf.writestr(name, data)
    return path


def special_info(name: str, mode: int) -> ZipInfo:
    info = ZipInfo(name)
    info.external_attr = mode << 16
    return info


def data_offset(path: Path, name: str) -> int:
    """File offset of *name*'s payload (after the local header)."""
    raw = path.read_bytes()
    with ZipFile(io.BytesIO(raw)) as zf:
        info = zf.getinfo(name)
    name_len, extra_len = struct.unpack_from("<HH", raw, info.header_offset + 26)
    return int(info.header_offset + 30 + name_len + extra_len)


def flip_byte(path: Path, offset: int) -> None:
    raw = bytearray(path.read_bytes())
    raw[offset] ^= 0xFF
    path.write_bytes(bytes(raw))


def set_compress_type(path: Path, name: str, method: int) -> None:
    """Rewrite *name*'s compression method in its local and central headers."""
    raw = bytearray(path.read_bytes())
    with ZipFile(io.BytesIO(bytes(raw))) as zf:
        info = zf.getinfo(name)
    struct.pack_into("<H", raw, info.header_offset + 8, method)
    central = raw.index(b"PK\x01\x02")
    while True:
        name_len = struct.unpack_from("<H", raw, central + 28)[0]
        if bytes(raw[central + 46 : central + 46 + name_len]) == name.encode():
            struct.pack_into("<H", raw, central + 10, method)
            break
        extra_len, comment_len = struct.unpack_from("<HH", raw, central + 30)
        central += 46 + name_len + extra_len + comment_len
    path.write_bytes(bytes(raw))


def set_flag_bits(path: Path, name: str, bits: int) -> None:
    """OR *bits* into *name*'s general-purpose flags (local and central)."""
    raw = bytearray(path.read_bytes())
    with ZipFile(io.BytesIO(bytes(raw))) as zf:
        info = zf.getinfo(name)
    (flags,) = struct.unpack_from("<H", raw, info.header_offset + 6)
    struct.pack_into("<H", raw, info.header_offset + 6, flags | bits)
    central = raw.index(b"PK\x01\x02")
    while True:
        name_len = struct.unpack_from("<H", raw, central + 28)[0]
        if bytes(raw[central + 46 : central + 46 + name_len]) == name.encode():
            (flags,) = struct.unpack_from("<H", raw, central + 8)
            struct.pack_into("<H", raw, central + 8, flags | bits)
            break
        extra_len, comment_len = struct.unpack_from("<HH", raw, central + 30)
        central += 46 + name_len + extra_len + comment_len
    path.write_bytes(bytes(raw))
