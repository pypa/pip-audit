from pathlib import Path

import pretend  # type: ignore
import pytest
from packaging.version import Version

from pip_audit._dependency_source import DependencySourceError, ResolveLibResolver, pyproject
from pip_audit._service import ResolvedDependency


def __init_pyproject(filename: Path, contents: str) -> Path:
    with open(filename, mode="w") as f:
        f.write(contents)
    return filename


@pytest.mark.online
def test_pyproject_source(req_file):
    filename = __init_pyproject(
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
    filename = __init_pyproject(
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

    filename = __init_pyproject(
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


def test_pyproject_source_duplicate_deps(req_file):
    filename = __init_pyproject(
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
    assert len(specs) == len(set(specs))
