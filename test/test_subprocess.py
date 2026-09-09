import sys

import pytest

from pip_audit._subprocess import CalledProcessError, run


def test_run_raises():
    with pytest.raises(CalledProcessError):
        run([sys.executable, "-c", "raise SystemExit(1)"])


def test_run_handles_split_multibyte_stdout():
    result = run(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'\\xc3'); "
            "sys.stdout.buffer.write(b'\\xa9')",
        ],
        log_stdout=True,
    )

    assert result == "é"


def test_run_handles_split_multibyte_stderr():
    with pytest.raises(CalledProcessError) as exc_info:
        run(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.buffer.write(b'\\xc3'); "
                "sys.stderr.buffer.write(b'\\xa9'); sys.exit(1)",
            ]
        )

    assert exc_info.value.stderr == "é"