import sys

import pytest

from pip_audit._subprocess import CalledProcessError, run


def test_run_raises():
    with pytest.raises(CalledProcessError):
        run(["false"])


def test_run_unicode_output():
    # Multi-byte UTF-8 output must be returned intact, without mojibake caused by
    # splitting the byte stream mid-codepoint (see #574).
    out = run(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write('日本語 🔒'.encode())"]
    )
    assert out == "日本語 🔒"
