import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List

import pip_api
import pretend  # type: ignore
import pytest
from packaging.version import Version

from pip_audit._dependency_source import pip
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service.interface import ResolvedDependency, SkippedDependency


def test_pip_source():
    source = pip.PipSource()

    # We're running under pytest, so we can safely assume that pytest is in
    # our execution environment.
    pytest_spec = ResolvedDependency(name="pytest", version=Version(pytest.__version__))

    specs = list(source.collect())
    assert pytest_spec in specs


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


def test_pip_source_invalid_version(monkeypatch):
    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(pip, "logger", logger)

    source = pip.PipSource()

    @dataclass(frozen=True)
    class MockDistribution:
        name: str
        version: str
        editable: bool = False

    # Return a distribution with a version that doesn't conform to PEP 440.
    # We should log a debug message and skip it.
    def mock_installed_distributions(
        local: bool, paths: List[os.PathLike]
    ) -> Dict[str, MockDistribution]:
        return {
            "pytest": MockDistribution("pytest", "0.1"),
            "pip-audit": MockDistribution("pip-audit", "1.0-ubuntu0.21.04.1"),
            "pip-api": MockDistribution("pip-api", "1.0"),
        }

    monkeypatch.setattr(pip_api, "installed_distributions", mock_installed_distributions)

    specs = list(source.collect())
    assert len(logger.debug.calls) == 1
    assert len(specs) == 3
    assert ResolvedDependency(name="pytest", version=Version("0.1")) in specs
    assert (
        SkippedDependency(
            name="pip-audit",
            skip_reason="Package has invalid version and could not be audited: "
            "pip-audit (1.0-ubuntu0.21.04.1)",
        )
        in specs
    )
    assert ResolvedDependency(name="pip-api", version=Version("1.0")) in specs


def test_pip_source_skips_editable(monkeypatch):
    source = pip.PipSource(skip_editable=True)

    @dataclass(frozen=True)
    class MockDistribution:
        name: str
        version: str
        editable: bool = False

    # Return a distribution with a version that doesn't conform to PEP 440.
    # We should log a debug message and skip it.
    def mock_installed_distributions(
        local: bool, paths: List[os.PathLike]
    ) -> Dict[str, MockDistribution]:
        return {
            "pytest": MockDistribution("pytest", "0.1"),
            "pip-audit": MockDistribution("pip-audit", "2.0.0", True),
            "pip-api": MockDistribution("pip-api", "1.0"),
        }

    monkeypatch.setattr(pip_api, "installed_distributions", mock_installed_distributions)

    specs = list(source.collect())
    assert ResolvedDependency(name="pytest", version=Version("0.1")) in specs
    assert (
        SkippedDependency(
            name="pip-audit",
            skip_reason="distribution marked as editable",
        )
        in specs
    )
    assert ResolvedDependency(name="pip-api", version=Version("1.0")) in specs


def test_pip_source_fix(monkeypatch):
    source = pip.PipSource()

    fix_version = ResolvedFixVersion(
        dep=ResolvedDependency(name="pip-api", version=Version("1.0")), version=Version("1.5")
    )

    def run_mock(args, **kwargs):
        assert " ".join(args) == f"{sys.executable} -m pip install pip-api==1.5"

    monkeypatch.setattr(subprocess, "run", run_mock)

    source.fix(fix_version)


def test_pip_source_fix_failure(monkeypatch):
    source = pip.PipSource()

    fix_version = ResolvedFixVersion(
        dep=ResolvedDependency(name="pip-api", version=Version("1.0")), version=Version("1.5")
    )

    def run_mock(args, **kwargs):
        assert " ".join(args) == f"{sys.executable} -m pip install pip-api==1.5"
        raise subprocess.CalledProcessError(-1, str())

    monkeypatch.setattr(subprocess, "run", run_mock)

    with pytest.raises(pip.PipFixError):
        source.fix(fix_version)
