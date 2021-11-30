import pytest
from packaging.version import Version

from pip_audit._service.interface import Dependency, ResolvedDependency, SkippedDependency


def test_dependency_typing():
    # there are only two subclasses of Dependency
    assert set(Dependency.__subclasses__()) == {ResolvedDependency, SkippedDependency}

    # Dependency itself cannot be initialized
    with pytest.raises(NotImplementedError):
        Dependency(name="explodes")

    r = ResolvedDependency(name="foo", version=Version("1.0.0"))
    assert r.name == "foo"
    assert r.canonical_name == "foo"
    assert not r.is_skipped()

    s = SkippedDependency(name="bar", skip_reason="unit test")
    assert s.name == "bar"
    assert s.canonical_name == "bar"
    assert s.is_skipped()


def test_vulnerability_service(vuln_service, spec):
    service = vuln_service()
    spec = spec("1.0.1")

    _, vulns = service.query(spec)
    assert len(vulns) == 1

    all_ = dict(service.query_all([spec]))
    assert len(all_) == 1
    assert len(all_[spec]) == 1


def test_vulnerability_service_no_results(vuln_service, spec):
    service = vuln_service()
    spec = spec("1.1.1")

    _, vulns = service.query(spec)
    assert len(vulns) == 0
