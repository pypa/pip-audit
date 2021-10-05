from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version
from pip_api import _parse_requirements

from pip_audit.dependency_source import (
    DependencyResolver,
    DependencyResolverError,
    DependencySourceError,
    ResolveLibResolver,
    requirement,
)
from pip_audit.service import Dependency


def test_requirement_source(monkeypatch):
    source = requirement.RequirementSource([Path("requirements.txt")], ResolveLibResolver())

    monkeypatch.setattr(_parse_requirements, "_read_file", lambda _: ["flask==2.0.1"])

    specs = list(source.collect())
    assert Dependency("flask", Version("2.0.1")) in specs


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
        def resolve(self, req: Requirement):
            raise DependencyResolverError

    source = requirement.RequirementSource([Path("requirements.txt")], MockResolver())

    monkeypatch.setattr(_parse_requirements, "_read_file", lambda _: ["flask==2.0.1"])

    with pytest.raises(DependencySourceError):
        list(source.collect())
