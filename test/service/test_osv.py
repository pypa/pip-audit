from typing import Dict, List

import pretend  # type: ignore
import pytest
from packaging.version import Version
from requests.exceptions import HTTPError

import pip_audit._service as service


def get_mock_session(func):
    class MockSession:
        def __init__(self, create_response):
            self.create_response = create_response

        def post(self, url, **kwargs):
            return self.create_response()

    return MockSession(func)


@pytest.mark.online
def test_osv():
    osv = service.OsvService()
    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        osv.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) > 0


@pytest.mark.online
def test_osv_uses_canonical_package_name():
    # OSV's API only recognizes canonicalized package names, so make sure
    # that our adapter is canonicalizing any dependencies passed into it.
    osv = service.OsvService()
    dep = service.ResolvedDependency("PyYAML", Version("5.3"))
    _, results = osv.query(dep)

    assert len(results) > 0


@pytest.mark.online
def test_osv_version_ranges():
    # Try a package with vulnerabilities that have an explicitly stated introduced and fixed
    # version
    osv = service.OsvService()
    dep = service.ResolvedDependency("ansible", Version("2.8.0"))
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        osv.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) > 0


@pytest.mark.online
def test_osv_multiple_pkg():
    osv = service.OsvService()
    deps: List[service.Dependency] = [
        service.ResolvedDependency("jinja2", Version("2.4.1")),
        service.ResolvedDependency("flask", Version("0.5")),
    ]
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        osv.query_all(iter(deps))
    )

    assert len(results) == 2
    assert deps[0] in results and deps[1] in results

    assert len(results[deps[0]]) > 0
    assert len(results[deps[1]]) > 0


@pytest.mark.online
def test_osv_no_vuln():
    osv = service.OsvService()
    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        osv.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0


def test_osv_error_response(monkeypatch):
    def raise_for_status():
        raise HTTPError

    response = pretend.stub(raise_for_status=pretend.call_recorder(raise_for_status))
    post = pretend.call_recorder(lambda *a, **kw: response)

    osv = service.OsvService()
    monkeypatch.setattr(osv.session, "post", post)

    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    with pytest.raises(service.ServiceError):
        dict(osv.query_all(iter([dep])))

    assert len(post.calls) == 1
    assert len(response.raise_for_status.calls) == 1


def test_osv_skipped_dep():
    osv = service.OsvService()
    dep = service.SkippedDependency(name="foo", skip_reason="skip-reason")
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        osv.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0
