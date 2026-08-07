"""
A thin `subprocess` wrapper for making long-running subprocesses more
responsive from the `pip-audit` CLI.
"""

import os.path
import subprocess
import threading
import time
from codecs import getincrementaldecoder
from collections.abc import Sequence
from io import BufferedReader
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


def _read_stream(stream: BufferedReader, output: bytearray) -> None:
    """
    Read a subprocess stream into the given output buffer.
    """
    while chunk := stream.read(8192):
        output.extend(chunk)


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

    stdout = bytearray()
    stderr = bytearray()

    # Run the process with unbuffered I/O, to make the poll-and-read loop below
    # more responsive.
    with Popen(args, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        assert process.stdout is not None
        assert process.stderr is not None

        stdout_thread = threading.Thread(target=_read_stream, args=(process.stdout, stdout))
        stderr_thread = threading.Thread(target=_read_stream, args=(process.stderr, stderr))
        stdout_thread.start()
        stderr_thread.start()

        stdout_decoder = getincrementaldecoder("utf-8")(errors="replace")
        stdout_decoded = ""
        stdout_decoded_len = 0

        while process.poll() is None:
            stdout_decoded += stdout_decoder.decode(bytes(stdout[stdout_decoded_len:]))
            stdout_decoded_len = len(stdout)
            state.update_state(
                f"Running {pretty_args}",
                stdout_decoded if log_stdout else None,
            )
            time.sleep(0.1)

        stdout_thread.join()
        stderr_thread.join()

        stdout_decoded += stdout_decoder.decode(bytes(stdout[stdout_decoded_len:]), final=True)
        state.update_state(
            f"Running {pretty_args}",
            stdout_decoded if log_stdout else None,
        )

        if process.returncode != 0:
            raise CalledProcessError(
                f"{pretty_args} exited with {process.returncode}",
                stderr=stderr.decode("utf-8", errors="replace"),
            )

    return stdout.decode("utf-8", errors="replace")
