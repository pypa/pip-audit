import pip_audit


def test_version():
    assert isinstance(pip_audit.__version__, str)
