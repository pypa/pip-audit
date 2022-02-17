from typing import Dict, List

import pretend  # type: ignore
import pytest
import requests
from packaging.version import Version

import pip_audit._service as service


def get_mock_session(func):
    class MockSession:
        def __init__(self, create_response):
            self.create_response = create_response

        def get(self, url, **kwargs):
            return self.create_response()

    return MockSession(func)


@pytest.mark.online
def test_pypi(cache_dir):
    pypi = service.PyPIService(cache_dir)
    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        pypi.query_all(iter([dep]))
    )
    assert len(results) == 1
    assert dep in results
    vulns = results[dep]
    assert len(vulns) > 0


@pytest.mark.online
def test_pypi_multiple_pkg(cache_dir):
    pypi = service.PyPIService(cache_dir)
    deps: List[service.Dependency] = [
        service.ResolvedDependency("jinja2", Version("2.4.1")),
        service.ResolvedDependency("flask", Version("0.5")),
    ]
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        pypi.query_all(iter(deps))
    )
    assert len(results) == 2
    assert deps[0] in results and deps[1] in results
    assert len(results[deps[0]]) > 0
    assert len(results[deps[1]]) > 0


def test_pypi_http_notfound(monkeypatch, cache_dir):
    # If we get a "not found" response, that means that we're querying a package or version that
    # isn't known to PyPI. If that's the case, we should just log a debug message and continue on
    # with the audit.
    def get_error_response():
        class MockResponse:
            # 404: Not Found
            status_code = 404

            def raise_for_status(self):
                raise requests.HTTPError

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "caching_session", lambda _: get_mock_session(get_error_response)
    )
    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(service.pypi, "logger", logger)

    pypi = service.PyPIService(cache_dir)
    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        pypi.query_all(iter([dep]))
    )
    assert len(results) == 1
    skipped_dep = service.SkippedDependency(
        name="jinja2",
        skip_reason="Dependency not found on PyPI and could not be audited: jinja2 (2.4.1)",
    )
    assert skipped_dep in results
    assert dep not in results
    assert len(results[skipped_dep]) == 0
    assert len(logger.debug.calls) == 1


def test_pypi_http_error(monkeypatch, cache_dir):
    # Any error response other than "not found" should raise an error.
    def get_error_response():
        class MockResponse:
            # 403: Forbidden
            status_code = 403

            def raise_for_status(self):
                raise requests.HTTPError

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "caching_session", lambda _: get_mock_session(get_error_response)
    )

    pypi = service.PyPIService(cache_dir)
    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    with pytest.raises(service.ServiceError):
        dict(pypi.query_all(iter([dep])))


def test_pypi_mocked_response(monkeypatch, cache_dir):
    def get_mock_response():
        class MockResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {
                    "vulnerabilities": [
                        {
                            "aliases": ["foo", "bar"],
                            "id": "VULN-0",
                            "details": "The first vulnerability",
                            "fixed_in": ["1.1", "1.4"],
                        }
                    ]
                }

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "caching_session", lambda _: get_mock_session(get_mock_response)
    )

    pypi = service.PyPIService(cache_dir)
    dep = service.ResolvedDependency("foo", Version("1.0"))
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        pypi.query_all(iter([dep]))
    )
    assert len(results) == 1
    assert dep in results
    assert len(results[dep]) == 1
    assert results[dep][0] == service.VulnerabilityResult(
        id="VULN-0",
        description="The first vulnerability",
        fix_versions=[Version("1.1"), Version("1.4")],
        aliases={"foo", "bar"},
    )


def test_pypi_no_vuln_key(monkeypatch, cache_dir):
    def get_mock_response():
        class MockResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {}

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "caching_session", lambda _: get_mock_session(get_mock_response)
    )

    pypi = service.PyPIService(cache_dir)
    dep = service.ResolvedDependency("foo", Version("1.0"))
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        pypi.query_all(iter([dep]))
    )
    assert len(results) == 1
    assert dep in results
    assert not results[dep]


def test_pypi_invalid_version(monkeypatch, cache_dir):
    def get_mock_response():
        class MockResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {
                    "vulnerabilities": [
                        {
                            "aliases": ["foo", "bar"],
                            "id": "VULN-0",
                            "details": "The first vulnerability",
                            "fixed_in": ["invalid_version"],
                        }
                    ]
                }

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "caching_session", lambda _: get_mock_session(get_mock_response)
    )

    pypi = service.PyPIService(cache_dir)
    dep = service.ResolvedDependency("foo", Version("1.0"))
    with pytest.raises(service.ServiceError):
        dict(pypi.query_all(iter([dep])))


def test_pypi_skipped_dep(cache_dir):
    pypi = service.PyPIService(cache_dir)
    dep = service.SkippedDependency(name="foo", skip_reason="skip-reason")
    results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
        pypi.query_all(iter([dep]))
    )
    assert len(results) == 1
    assert dep in results
    vulns = results[dep]
    assert len(vulns) == 0


@pytest.mark.online
def test_pypi_hashed_dep(cache_dir):
    pypi = service.PyPIService(cache_dir)
    dep = service.ResolvedDependency(
        "flask",
        Version("2.0.1"),
        hashes={"sha256": ["a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9"]},
    )
    results = dict(pypi.query_all(iter([dep])))
    assert len(results) == 1
    assert dep in results
    vulns = results[dep]
    assert len(vulns) == 0


@pytest.mark.online
def test_pypi_hashed_dep_mismatch(cache_dir):
    pypi = service.PyPIService(cache_dir)
    dep = service.ResolvedDependency(
        "flask",
        Version("2.0.1"),
        hashes={"sha256": ["mismatched-hash"]},
    )
    with pytest.raises(service.ServiceError):
        dict(pypi.query_all(iter([dep])))


def test_pypi_hashed_dep_no_release_data(cache_dir, monkeypatch):
    def get_mock_response():
        class MockResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {
                    "releases": {},
                    "vulnerabilities": [
                        {
                            "id": "VULN-0",
                            "details": "The first vulnerability",
                            "fixed_in": ["1.1"],
                        }
                    ],
                }

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "caching_session", lambda _: get_mock_session(get_mock_response)
    )

    pypi = service.PyPIService(cache_dir)
    dep = service.ResolvedDependency("foo", Version("1.0"), hashes={"sha256": ["package-hash"]})
    with pytest.raises(service.ServiceError):
        dict(pypi.query_all(iter([dep])))
