import pip_api
import pretend
import pytest
from packaging.version import Version

import pip_audit
from pip_audit._dependency_source import pip
from pip_audit._service.interface import Dependency


def test_pip_source():
    source = pip.PipSource()

    # We're running under pytest, so we can safely assume that pytest is in
    # our execution environment. We're also running pip_audit itself, so we
    # can safely test for ourselves.
    pytest_spec = Dependency(name="pytest", version=Version(pytest.__version__))
    pip_audit_spec = Dependency(name="pip-audit", version=Version(pip_audit.__version__))

    specs = list(source.collect())
    assert pytest_spec in specs
    assert pip_audit_spec in specs


def test_pip_source_warns_about_old_pip(monkeypatch):
    # Rather than hack around with virtualenvs and install a very old pip,
    # simply lie about how old ours is.
    monkeypatch.setattr(pip, "_PIP_VERSION", Version("1.0.0"))
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(pip, "logger", logger)

    pip.PipSource()
    assert len(logger.warning.calls) == 1


def test_pip_source_pip_api_failure(monkeypatch):
    source = pip.PipSource()

    def explode():
        raise ValueError

    monkeypatch.setattr(pip_api, "installed_distributions", explode)

    with pytest.raises(pip.PipSourceError):
        list(source.collect())
