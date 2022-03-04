from pathlib import Path
from typing import List

import pretend  # type: ignore
import pytest
from packaging.requirements import Requirement
from packaging.version import Version

from pip_audit._dependency_source import (
    DependencyResolver,
    DependencyResolverError,
    DependencySourceError,
    ResolveLibResolver,
    pyproject,
)
from pip_audit._service import Dependency, ResolvedDependency


def _init_pyproject(filename: Path, contents: str) -> Path:
    with open(filename, mode="w") as f:
        f.write(contents)
    return filename


@pytest.mark.online
def test_pyproject_source(req_file):
    filename = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask==2.0.1"
]
    """,
    )
    source = pyproject.PyProjectSource(filename, ResolveLibResolver())
    specs = list(source.collect())
    assert ResolvedDependency("flask", Version("2.0.1")) in specs


def test_pyproject_source_no_project_section(req_file):
    filename = _init_pyproject(
        req_file(),
        """
[some_other_section]
dependencies = [
  "flask==2.0.1"
]
    """,
    )
    source = pyproject.PyProjectSource(filename, ResolveLibResolver())
    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_pyproject_source_no_deps(monkeypatch, req_file):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(pyproject, "logger", logger)

    filename = _init_pyproject(
        req_file(),
        """
[project]
    """,
    )
    source = pyproject.PyProjectSource(filename, ResolveLibResolver())
    specs = list(source.collect())
    assert not specs

    # We log a warning when we find a `pyproject.toml` file with no dependencies
    assert len(logger.warning.calls) == 1


@pytest.mark.online
def test_pyproject_source_duplicate_deps(req_file):
    # Click is a dependency of Flask. We should check that the dependencies of Click aren't returned
    # twice.
    filename = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask",
  "click",
]
""",
    )
    source = pyproject.PyProjectSource(filename, ResolveLibResolver())
    specs = list(source.collect())

    # Check that the list of dependencies is already deduplicated
    assert len(specs) == len(set(specs))


def test_pyproject_source_resolver_error(monkeypatch, req_file):
    class MockResolver(DependencyResolver):
        def resolve(self, req: Requirement) -> List[Dependency]:
            raise DependencyResolverError

    filename = _init_pyproject(
        req_file(),
        """
[project]
dependencies = [
  "flask==2.0.1"
]
""",
    )
    source = pyproject.PyProjectSource(filename, MockResolver())
    with pytest.raises(DependencySourceError):
        list(source.collect())
