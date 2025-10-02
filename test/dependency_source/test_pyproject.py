from __future__ import annotations

from pathlib import Path

import pretend  # type: ignore
import pytest
import tomli
from packaging.version import Version

from pip_audit._dependency_source import (
    DependencyFixError,
    DependencySourceError,
    pyproject,
)
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import ResolvedDependency
from pip_audit._state import AuditState
from pip_audit._virtual_env import VirtualEnvError


def _init_pyproject(filename: Path, contents: str) -> pyproject.PyProjectSource:
    with open(filename, mode="w") as f:
        f.write(contents)
    return pyproject.PyProjectSource(filename)


def _check_file(filename: Path, expected_contents: dict) -> None:
    with open(filename, "rb") as f:
        assert tomli.load(f) == expected_contents


@pytest.mark.online
def test_pyproject_source(req_file):
    source = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask==2.0.1"
]
    """,
    )
    specs = list(source.collect())
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs


def test_pyproject_source_no_project_section(req_file):
    source = _init_pyproject(
        req_file(),
        """
[some_other_section]
dependencies = [
  "flask==2.0.1"
]
    """,
    )
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_pyproject_source_no_deps(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(pyproject, "logger", logger)

    source = _init_pyproject(
        req_file(),
        """
[project]
    """,
    )
    specs = list(source.collect())
    assert not specs

    # We log a warning when we find a `pyproject.toml` file with no dependencies
    assert len(logger.warning.calls) == 1


@pytest.mark.online
def test_pyproject_source_duplicate_deps(req_file):
    # Click is a dependency of Flask. We should check that the dependencies of Click aren't returned
    # twice.
    source = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask",
  "click",
]
""",
    )
    specs = list(source.collect())

    # Check that the list of dependencies is already deduplicated
    assert len(specs) == len(set(specs))


def test_pyproject_source_virtualenv_error(monkeypatch, req_file):
    class MockVirtualEnv:
        def __init__(self, install_args: list[str], state: AuditState) -> None:
            pass

        def create(self, dir: Path) -> None:
            raise VirtualEnvError

    source = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask==2.0.1"
]
""",
    )
    monkeypatch.setattr(pyproject, "VirtualEnv", MockVirtualEnv)
    with pytest.raises(DependencySourceError):
        list(source.collect())


@pytest.mark.online
def test_pyproject_source_fix(req_file):
    source = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask==0.5"
]
""",
    )
    fix = ResolvedFixVersion(
        dep=ResolvedDependency(name="flask", version=Version("0.5")),
        version=Version("1.0"),
    )
    source.fix(fix)
    _check_file(source.filename, {"project": {"dependencies": ["flask==1.0"]}})


def test_pyproject_source_fix_no_project_section(req_file):
    source = _init_pyproject(
        req_file(),
        """
[some_other_section]
dependencies = [
  "flask==2.0.1"
]
""",
    )
    fix = ResolvedFixVersion(
        dep=ResolvedDependency(name="flask", version=Version("0.5")),
        version=Version("1.0"),
    )
    with pytest.raises(DependencyFixError):
        source.fix(fix)


def test_pyproject_source_fix_no_deps(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(pyproject, "logger", logger)

    source = _init_pyproject(
        req_file(),
        """
[project]
""",
    )
    fix = ResolvedFixVersion(
        dep=ResolvedDependency(name="flask", version=Version("0.5")),
        version=Version("1.0"),
    )
    source.fix(fix)

    # We log a warning when we find a `pyproject.toml` file with no dependencies
    assert len(logger.warning.calls) == 1
    _check_file(source.filename, {"project": {}})


@pytest.mark.online
def test_pyproject_source_with_single_extra(req_file):
    # Test that we can audit optional dependencies with a single extra
    source = pyproject.PyProjectSource(filename=req_file(), extras=["dev"])
    with open(source.filename, mode="w") as f:
        f.write("""
[project]
dependencies = [
  "flask==2.0.1"
]

[project.optional-dependencies]
dev = [
  "pytest==7.0.0"
]
""")
    specs = list(source.collect())
    # Should include both main and dev dependencies
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs
    assert ResolvedDependency("pytest", Version("7.0.0")) in specs


@pytest.mark.online
def test_pyproject_source_with_multiple_extras(req_file):
    # Test that we can audit optional dependencies with multiple extras
    source = pyproject.PyProjectSource(filename=req_file(), extras=["dev", "test"])
    with open(source.filename, mode="w") as f:
        f.write("""
[project]
dependencies = [
  "flask==2.0.1"
]

[project.optional-dependencies]
dev = [
  "pytest==7.0.0"
]
test = [
  "coverage==6.0.0"
]
""")
    specs = list(source.collect())
    # Should include main, dev, and test dependencies
    assert ResolvedDependency("Flask", Version("2.0.1")) in specs
    assert ResolvedDependency("pytest", Version("7.0.0")) in specs
    assert ResolvedDependency("coverage", Version("6.0.0")) in specs


def test_pyproject_source_with_nonexistent_extra(monkeypatch, req_file):
    # Test that non-existent extras trigger an error
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(pyproject, "logger", logger)

    source = pyproject.PyProjectSource(filename=req_file(), extras=["nonexistent"])
    with open(source.filename, mode="w") as f:
        f.write("""
[project]
dependencies = [
  "flask==2.0.1"
]

[project.optional-dependencies]
dev = [
  "pytest==7.0.0"
]
""")

    # Should raise an error for non-existent extras
    with pytest.raises(DependencySourceError, match="extra.*nonexistent.*not found"):
        list(source.collect())


@pytest.mark.online
def test_pyproject_source_extras_no_optional_dependencies(req_file):
    # Test when extras are requested but no optional-dependencies section exists
    source = pyproject.PyProjectSource(filename=req_file(), extras=["dev"])
    with open(source.filename, mode="w") as f:
        f.write("""
[project]
dependencies = [
  "flask==2.0.1"
]
""")

    # Should raise an error when extras are requested but section doesn't exist
    with pytest.raises(DependencySourceError, match="optional-dependencies.*not found"):
        list(source.collect())


@pytest.mark.online
def test_pyproject_source_fix_with_extras(req_file):
    # Test that fixing works with extras
    source = pyproject.PyProjectSource(filename=req_file(), extras=["dev"])
    with open(source.filename, mode="w") as f:
        f.write("""
[project]
dependencies = [
  "flask==0.5"
]

[project.optional-dependencies]
dev = [
  "pytest==6.0.0"
]
""")

    fix = ResolvedFixVersion(
        dep=ResolvedDependency(name="pytest", version=Version("6.0.0")),
        version=Version("7.0.0"),
    )
    source.fix(fix)

    # Check that the optional dependency was fixed
    with open(source.filename, "rb") as f:
        content = tomli.load(f)
        assert content["project"]["optional-dependencies"]["dev"] == ["pytest==7.0.0"]
