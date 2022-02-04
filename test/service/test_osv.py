import itertools
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


def test_osv_uses_canonical_package_name():
    # OSV's API only recognizes canonicalized package names, so make sure
    # that our adapter is canonicalizing any dependencies passed into it.
    osv = service.OsvService()
    dep = service.ResolvedDependency("PyYAML", Version("5.3"))
    _, results = osv.query(dep)

    assert len(results) > 0


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


def test_osv_unique_aliases(monkeypatch, cache_dir):
    def get_mock_response():
        class MockResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {
                    "vulns": [
                        {
                            "aliases": ["alias-1"],
                            "id": "PYSEC-0",
                            "details": "The first vulnerability",
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "foo"},
                                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.1"}]}],
                                }
                            ],
                        },
                        {
                            "aliases": ["alias-1", "alias-2"],
                            "id": "PYSEC-1",
                            "details": "The second vulnerability",
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "foo"},
                                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.1"}]}],
                                }
                            ],
                        },
                    ]
                }

        return MockResponse()

    monkeypatch.setattr(
        service.osv, "caching_session", lambda *a, **kw: get_mock_session(get_mock_response)
    )

    osv = service.OsvService(cache_dir)
    dep = service.ResolvedDependency("foo", Version("1.0"))
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        osv.query_all(iter([dep]))
    )

    assert len(results) == 1
    vulns = results[dep]
    assert len(vulns) == 1
    assert vulns[0].id == "PYSEC-0"
    assert vulns[0].aliases == ["alias-1"]


# Parametrize on all possible response orders here, to ensure that our
# vulnerability uniquing/selection is not order dependent.
@pytest.mark.parametrize(
    "vulns",
    itertools.permutations(
        [
            {
                "aliases": ["alias-1"],
                "id": "VULN-0",
                "details": "The first vulnerability",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "foo"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.1"}]}],
                    }
                ],
            },
            {
                "aliases": ["alias-1", "alias-2"],
                "id": "PYSEC-XYZ",
                "details": "The second vulnerability",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "foo"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.1"}]}],
                    }
                ],
            },
            {
                "aliases": ["alias-3"],
                "id": "VULN-ABC",
                "details": "The third vulnerability",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "foo"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.1"}]}],
                    }
                ],
            },
        ]
    ),
)
def test_osv_unique_aliases_prefer_pysec(monkeypatch, cache_dir, vulns):
    def get_mock_response():
        class MockResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"vulns": vulns}

        return MockResponse()

    monkeypatch.setattr(
        service.osv, "caching_session", lambda *a, **kw: get_mock_session(get_mock_response)
    )

    osv = service.OsvService(cache_dir)
    dep = service.ResolvedDependency("foo", Version("1.0"))
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        osv.query_all(iter([dep]))
    )

    assert len(results) == 1
    vulns = results[dep]
    assert len(vulns) == 2
    assert vulns[0].id == "PYSEC-XYZ"
    assert vulns[0].aliases == ["alias-1", "alias-2"]
    assert vulns[1].id == "VULN-ABC"
    assert vulns[1].aliases == ["alias-3"]
