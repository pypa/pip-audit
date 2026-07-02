import sys

import pytest

from pip_audit._subprocess import CalledProcessError, run


class RecordingState:
    def __init__(self):
        self.logs = []

    def update_state(self, message, logs=None):
        self.logs.append(logs)


def test_run_raises():
    with pytest.raises(CalledProcessError):
        run(["false"])


def test_run_handles_split_multibyte_stdout():
    state = RecordingState()

    stdout = run(
        [
            sys.executable,
            "-c",
            (
                "import sys, time; "
                "data = 'é'.encode(); "
                "sys.stdout.buffer.write(data[:1]); "
                "sys.stdout.flush(); "
                "time.sleep(0.2); "
                "sys.stdout.buffer.write(data[1:]); "
                "sys.stdout.flush()"
            ),
        ],
        log_stdout=True,
        state=state,
    )

    assert stdout == "é"
    assert "\ufffd" not in "".join(log or "" for log in state.logs)


def test_run_handles_split_multibyte_stderr():
    with pytest.raises(CalledProcessError) as excinfo:
        run(
            [
                sys.executable,
                "-c",
                (
                    "import sys, time; "
                    "data = 'é'.encode(); "
                    "sys.stderr.buffer.write(data[:1]); "
                    "sys.stderr.flush(); "
                    "time.sleep(0.2); "
                    "sys.stderr.buffer.write(data[1:]); "
                    "sys.stderr.flush(); "
                    "sys.exit(1)"
                ),
            ],
        )

    assert excinfo.value.stderr == "é"
