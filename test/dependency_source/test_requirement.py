from pathlib import Path

from packaging.version import Version
from pip_api import _parse_requirements

from pip_audit.dependency_source import ResolveLibResolver, requirement
from pip_audit.service import Dependency


def test_requirement_source(monkeypatch):
    source = requirement.RequirementSource([Path("requirements.txt")], ResolveLibResolver())

    monkeypatch.setattr(_parse_requirements, "_read_file", lambda _: ["flask==2.0.1"])

    specs = list(source.collect())
    assert Dependency("flask", Version("2.0.1")) in specs
