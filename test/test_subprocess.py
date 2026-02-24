import sys

import pytest

from pip_audit._subprocess import CalledProcessError, run


def test_run_raises():
    with pytest.raises(CalledProcessError):
        run(["false"])


def test_run_handles_unicode_stdout():
    # Print a multibyte UTF-8 sequence to stdout; this used to be fragile under
    # a manual poll/read loop that could split codepoints across reads.
    out = run([sys.executable, "-c", "print('☃️🚀')"])
    assert "☃️🚀" in out


def test_run_handles_unicode_stdout_with_log_stdout():
    # Same as above, but exercises the log_stdout path.
    out = run([sys.executable, "-c", "print('☃️🚀')"], log_stdout=True)
    assert "☃️🚀" in out
