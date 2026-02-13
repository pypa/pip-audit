"""
A thin `subprocess` wrapper for making long-running subprocesses more
responsive from the `pip-audit` CLI.
"""

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

    # Run the process with unbuffered I/O and use `communicate()` to avoid
    # deadlocks while reading full stdout/stderr.
    with Popen(args, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        state.update_state(f"Running {pretty_args}")

        stdout, stderr = process.communicate()

        state.update_state(
            f"Running {pretty_args}",
            stdout.decode(errors="replace") if log_stdout else None,
        )

        if process.returncode != 0:
            raise CalledProcessError(
                f"{pretty_args} exited with {process.returncode}",
                stderr=stderr.decode(errors="replace"),
            )

    return stdout.decode("utf-8", errors="replace")
