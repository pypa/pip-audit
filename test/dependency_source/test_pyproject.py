from pathlib import Path
from typing import List

import pretend  # type: ignore
import pytest
import toml
from packaging.requirements import Requirement
from packaging.version import Version

from pip_audit._dependency_source import (
    DependencyResolver,
    DependencyResolverError,
    DependencySourceError,
    ResolveLibResolver,
    pyproject,
)
from pip_audit._dependency_source.interface import DependencyFixError, ResolvedFixVersion
from pip_audit._service import Dependency, ResolvedDependency


def _init_pyproject(filename: Path, contents: str) -> pyproject.PyProjectSource:
    with open(filename, mode="w") as f:
        f.write(contents)
    return pyproject.PyProjectSource(filename, ResolveLibResolver())


def _check_file(filename: Path, expected_contents: dict) -> None:
    with open(filename, mode="r") as f:
        assert toml.load(f) == expected_contents


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
    assert ResolvedDependency("flask", Version("2.0.1")) in specs


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


def test_pyproject_source_resolver_error(monkeypatch, req_file):
    class MockResolver(DependencyResolver):
        def resolve(self, req: Requirement) -> List[Dependency]:
            raise DependencyResolverError

    source = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask==2.0.1"
]
""",
    )
    source.resolver = MockResolver()
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
        dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
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
        dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
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
        dep=ResolvedDependency(name="flask", version=Version("0.5")), version=Version("1.0")
    )
    source.fix(fix)

    # We log a warning when we find a `pyproject.toml` file with no dependencies
    assert len(logger.warning.calls) == 1
    _check_file(source.filename, {"project": {}})
