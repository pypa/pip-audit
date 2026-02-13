import sys

import pytest

from pip_audit._subprocess import CalledProcessError, run


def test_run_raises():
    with pytest.raises(CalledProcessError):
        run([sys.executable, "-c", "raise SystemExit(1)"])


def test_run_returns_stdout():
    stdout = run([sys.executable, "-c", "print('hello')"])
    assert stdout == "hello\n"


def test_run_preserves_valid_utf8_output():
    # A minimal repro for the UTF-8 "split" scenario: output a two-byte UTF-8
    # sequence such that the first byte lands at the 4096 boundary.
    code = (
        "import sys\n"
        "sys.stdout.buffer.write(b'a' * 4095 + b'\\xc2')\n"
        "sys.stdout.buffer.write(b'\\xae')\n"
        "sys.stdout.flush()\n"
    )

    stdout = run([sys.executable, "-c", code])

    assert "®" in stdout
    assert "�" not in stdout
