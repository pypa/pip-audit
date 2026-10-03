import sys

import pytest

from pip_audit._subprocess import CalledProcessError, run


def test_run_raises():
    with pytest.raises(CalledProcessError):
        run([sys.executable, "-c", "raise SystemExit(1)"])


def test_run_preserves_multibyte_utf8_output():
    code = "import sys; sys.stdout.buffer.write(b'a' * 4095 + '€'.encode())"

    assert run([sys.executable, "-c", code]) == "a" * 4095 + "€"
