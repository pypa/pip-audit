"""
A thin `subprocess` wrapper for making long-running subprocesses more
responsive from the `pip-audit` CLI.
"""

import os.path
import queue
import subprocess
import threading
import time
from collections.abc import Sequence
from codecs import getincrementaldecoder
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


def _read_stream(stream: object, output: queue.Queue[bytes | None]) -> None:
    """
    Read a subprocess stream in a background thread.
    """
    while True:
        chunk = stream.read(8192)  # type: ignore
        if not chunk:
            output.put(None)
            return
        output.put(chunk)


def run(
    args: Sequence[str],
    *,
    log_stdout: bool = False,
    state: AuditState = AuditState(),
) -> str:
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

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    stdout_queue: queue.Queue[bytes | None] = queue.Queue()
    stderr_queue: queue.Queue[bytes | None] = queue.Queue()

    stdout_decoder = getincrementaldecoder("utf-8")(errors="replace")

    # Run the process with unbuffered I/O so output can still be reported
    # promptly while both streams are drained concurrently.
    with Popen(
        args,
        bufsize=0,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        stdout_thread = threading.Thread(
            target=_read_stream,
            args=(process.stdout, stdout_queue),
        )
        stderr_thread = threading.Thread(
            target=_read_stream,
            args=(process.stderr, stderr_queue),
        )

        stdout_thread.start()
        stderr_thread.start()

        stdout_done = False
        stderr_done = False
        progress_output = ""

        while not (stdout_done and stderr_done):
            try:
                while True:
                    chunk = stdout_queue.get_nowait()

                    if chunk is None:
                        stdout_done = True
                        break

                    stdout_chunks.append(chunk)

                    if log_stdout:
                        progress_output += stdout_decoder.decode(chunk)

            except queue.Empty:
                pass

            try:
                while True:
                    chunk = stderr_queue.get_nowait()

                    if chunk is None:
                        stderr_done = True
                        break

                    stderr_chunks.append(chunk)

            except queue.Empty:
                pass

            if log_stdout:
                state.update_state(
                    f"Running {pretty_args}",
                    progress_output,
                )

            if not (stdout_done and stderr_done):
                time.sleep(0.01)

        stdout_thread.join()
        stderr_thread.join()

        # Ensure the subprocess has fully terminated before checking its
        # return code.
        process.wait()

        # Flush any incomplete UTF-8 sequence held by the incremental decoder.
        if log_stdout:
            progress_output += stdout_decoder.decode(b"", final=True)
            state.update_state(
                f"Running {pretty_args}",
                progress_output,
            )

        stdout = b"".join(stdout_chunks)
        stderr = b"".join(stderr_chunks)

        if process.returncode != 0:
            raise CalledProcessError(
                f"{pretty_args} exited with {process.returncode}",
                stderr=stderr.decode("utf-8", errors="replace"),
            )

    return stdout.decode("utf-8", errors="replace")