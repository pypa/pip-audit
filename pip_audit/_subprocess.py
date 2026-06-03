"""
A thin `subprocess` wrapper for making long-running subprocesses more
responsive from the `pip-audit` CLI.
"""

import codecs
import os.path
import subprocess
from collections.abc import Sequence
from subprocess import Popen

from ._state import AuditState


class CalledProcessError(Exception):
    """
    Raised if the underlying subprocess created by `run` exits with a nonzero code.
    """

    def __init__(self, msg: str, *, stderr: str) -> None:
        """
        Create a new `CalledProcessError`.
        """
        super().__init__(msg)
        self.stderr = stderr


def run(args: Sequence[str], *, log_stdout: bool = False, state: AuditState = AuditState()) -> str:
    """
    Execute the given arguments.

    Uses `state` to provide feedback on the subprocess's status.

    Raises a `CalledProcessError` if the subprocess fails. Otherwise, returns
    the process's `stdout` stream as a string.
    """

    # NOTE(ww): We frequently run commands inside of ephemeral virtual environments,
    # which have long absolute paths on some platforms. These make for confusing
    # state updates, so we trim the first argument down to its basename.
    pretty_args = " ".join([os.path.basename(args[0]), *args[1:]])

    terminated = False
    stdout = b""
    stderr = b""

    # We accumulate raw bytes for the final result, but the live progress
    # updates need a textual view of `stdout` so far. Decoding the raw buffer
    # on each iteration is unsound: an unbuffered read can stop in the middle
    # of a multi-byte UTF-8 sequence, so a plain `bytes.decode` would either
    # raise or (with `errors="replace"`) emit a replacement character for a
    # codepoint that is actually valid once the rest of its bytes arrive.
    # An incremental decoder holds those trailing bytes back until the
    # sequence is complete, so we only ever surface fully-decoded codepoints.
    # See https://github.com/pypa/pip-audit/issues/574.
    stdout_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    decoded_stdout = ""

    # Run the process with unbuffered I/O, to make the poll-and-read loop below
    # more responsive.
    with Popen(args, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        # NOTE: We use `poll()` to control this loop instead of the `read()` call
        # to prevent deadlocks. Similarly, `read(size)` will return an empty bytes
        # once `stdout` hits EOF, so we don't have to worry about that blocking.
        while not terminated:
            terminated = process.poll() is not None
            chunk = process.stdout.read()  # type: ignore
            stdout += chunk
            stderr += process.stderr.read()  # type: ignore
            if log_stdout:
                # `final=terminated` flushes any pending (incomplete) bytes once
                # the stream is at EOF, matching the previous replace behaviour.
                decoded_stdout += stdout_decoder.decode(chunk, final=terminated)
                state.update_state(
                    f"Running {pretty_args}",
                    decoded_stdout,
                )
            else:
                state.update_state(f"Running {pretty_args}")

        if process.returncode != 0:
            raise CalledProcessError(
                f"{pretty_args} exited with {process.returncode}",
                stderr=stderr.decode(errors="replace"),
            )

    return stdout.decode("utf-8", errors="replace")
