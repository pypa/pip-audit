import pytest

from pip_audit._subprocess import CalledProcessError, run


def test_run_raises():
    with pytest.raises(CalledProcessError):
        run(["false"])
