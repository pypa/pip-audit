from packaging.version import Version

import pip_audit._util as util


def test_python_version():
    v = util.python_version()
    assert v is not None
    assert isinstance(v, Version)
