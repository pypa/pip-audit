from pathlib import Path
from typing import List

import pytest
from packaging.requirements import Requirement
from packaging.version import Version
from pip_api import _parse_requirements

from pip_audit._dependency_source import (
    DependencyResolver,
    DependencyResolverError,
    DependencySourceError,
    ResolveLibResolver,
    requirement,
)
from pip_audit._service import Dependency, ResolvedDependency


def test_requirement_source(monkeypatch):
    source = requirement.RequirementSource([Path("requirements.txt")], ResolveLibResolver())

    monkeypatch.setattr(_parse_requirements, "_read_file", lambda _: ["flask==2.0.1"])

    specs = list(source.collect())
    assert ResolvedDependency("flask", Version("2.0.1")) in specs


def test_requirement_source_multiple_files(monkeypatch):
    file1 = "requirements1.txt"
    file2 = "requirements2.txt"
    file3 = "requirements3.txt"

    source = requirement.RequirementSource(
        [Path(file1), Path(file2), Path(file3)],
        ResolveLibResolver(),
    )

    def read_file_mock(f):
        filename = f.name
        if filename == file1:
            return ["flask==2.0.1"]
        elif filename == file2:
            return ["requests==2.8.1"]
        else:
            assert filename == file3
            return ["pip-api==0.0.22\n", "packaging==21.0"]

    monkeypatch.setattr(_parse_requirements, "_read_file", read_file_mock)

    specs = list(source.collect())
    assert ResolvedDependency("flask", Version("2.0.1")) in specs
    assert ResolvedDependency("requests", Version("2.8.1")) in specs
    assert ResolvedDependency("pip-api", Version("0.0.22")) in specs
    assert ResolvedDependency("packaging", Version("21.0")) in specs


def test_requirement_source_parse_error(monkeypatch):
    source = requirement.RequirementSource([Path("requirements.txt")], ResolveLibResolver())

    # Duplicate dependencies aren't allowed in a requirements file so we should expect the parser to
    # raise here
    monkeypatch.setattr(
        _parse_requirements, "_read_file", lambda _: ["flask==2.0.1\n", "flask==2.0.0"]
    )

    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_resolver_error(monkeypatch):
    # Pass the requirement source a resolver that automatically raises errors
    class MockResolver(DependencyResolver):
        def resolve(self, req: Requirement) -> List[Dependency]:
            raise DependencyResolverError

    source = requirement.RequirementSource([Path("requirements.txt")], MockResolver())

    monkeypatch.setattr(_parse_requirements, "_read_file", lambda _: ["flask==2.0.1"])

    with pytest.raises(DependencySourceError):
        list(source.collect())


def test_requirement_source_duplicate_dependencies(monkeypatch):
    source = requirement.RequirementSource(
        [Path("requirements1.txt"), Path("requirements2.txt")], ResolveLibResolver()
    )

    # Return the same requirements for both files
    monkeypatch.setattr(_parse_requirements, "_read_file", lambda _: ["flask==2.0.1"])

    specs = list(source.collect())

    # If the dependency list has duplicates, then converting to a set will reduce the length of the
    # collection
    assert len(specs) == len(set(specs))
