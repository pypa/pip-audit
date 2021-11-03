import tempfile
from typing import List, Optional

import pretend
import pytest
import requests
from packaging.version import Version

import pip_audit.service as service

cache_dir: Optional[tempfile.TemporaryDirectory] = None


def setup_function(function):
    global cache_dir
    cache_dir = tempfile.TemporaryDirectory()


def teardown_function(function):
    cache_dir.cleanup()


def get_mock_session(func):
    class MockSession:
        def __init__(self, create_response):
            self.create_response = create_response

        def get(self, url):
            return self.create_response()

    return MockSession(func)


def test_pypi():
    pypi = service.PyPIService(cache_dir)
    dep = service.Dependency("jinja2", Version("2.4.1"))
    results: List[service.VulnerabilityResult] = dict(pypi.query_all([dep]))
    assert len(results) == 1
    assert dep in results
    vulns = results[dep]
    assert len(vulns) > 0


def test_pypi_multiple_pkg():
    pypi = service.PyPIService(cache_dir)
    deps: List[service.Dependency] = [
        service.Dependency("jinja2", Version("2.4.1")),
        service.Dependency("flask", Version("0.5")),
    ]
    results: List[service.VulnerabilityResult] = dict(pypi.query_all(deps))
    assert len(results) == 2
    assert deps[0] in results and deps[1] in results
    assert len(results[deps[0]]) > 0
    assert len(results[deps[1]]) > 0


def test_pypi_http_notfound(monkeypatch):
    # If we get a "not found" response, that means that we're querying a package or version that
    # isn't known to PyPI. If that's the case, we should just log a warning and continue on with
    # the audit.
    def get_error_response():
        class MockResponse:
            # 404: Not Found
            status_code = 404

            def raise_for_status(self):
                raise requests.HTTPError

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "_get_cached_session", lambda _: get_mock_session(get_error_response)
    )
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(service.pypi, "logger", logger)

    pypi = service.PyPIService(cache_dir)
    dep = service.Dependency("jinja2", Version("2.4.1"))
    results = dict(pypi.query_all([dep]))
    assert len(results) == 1
    assert dep in results
    assert len(results[dep]) == 0
    assert len(logger.warning.calls) == 1


def test_pypi_http_error(monkeypatch):
    # Any error response other than "not found" should raise an error.
    def get_error_response():
        class MockResponse:
            # 403: Forbidden
            status_code = 403

            def raise_for_status(self):
                raise requests.HTTPError

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "_get_cached_session", lambda _: get_mock_session(get_error_response)
    )

    pypi = service.PyPIService(cache_dir)
    dep = service.Dependency("jinja2", Version("2.4.1"))
    with pytest.raises(service.ServiceError):
        dict(pypi.query_all([dep]))


def test_pypi_mocked_response(monkeypatch):
    def get_mock_response():
        class MockResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {
                    "vulnerabilities": [
                        {
                            "id": "VULN-0",
                            "details": "The first vulnerability",
                            "fixed_in": ["1.1", "1.4"],
                        }
                    ]
                }

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "_get_cached_session", lambda _: get_mock_session(get_mock_response)
    )

    pypi = service.PyPIService(cache_dir)
    dep = service.Dependency("foo", Version("1.0"))
    results: List[service.VulnerabilityResult] = dict(pypi.query_all([dep]))
    assert len(results) == 1
    assert dep in results
    assert len(results[dep]) == 1
    assert results[dep][0] == service.VulnerabilityResult(
        id="VULN-0",
        description="The first vulnerability",
        fix_versions=[Version("1.1"), Version("1.4")],
    )


def test_pypi_no_vuln_key(monkeypatch):
    def get_mock_response():
        class MockResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {}

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "_get_cached_session", lambda _: get_mock_session(get_mock_response)
    )

    pypi = service.PyPIService(cache_dir)
    dep = service.Dependency("foo", Version("1.0"))
    results: List[service.VulnerabilityResult] = dict(pypi.query_all([dep]))
    assert len(results) == 1
    assert dep in results
    assert not results[dep]


def test_pypi_invalid_version(monkeypatch):
    def get_mock_response():
        class MockResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {
                    "vulnerabilities": [
                        {
                            "id": "VULN-0",
                            "details": "The first vulnerability",
                            "fixed_in": ["invalid_version"],
                        }
                    ]
                }

        return MockResponse()

    monkeypatch.setattr(
        service.pypi, "_get_cached_session", lambda _: get_mock_session(get_mock_response)
    )

    pypi = service.PyPIService(cache_dir)
    dep = service.Dependency("foo", Version("1.0"))
    with pytest.raises(service.ServiceError):
        dict(pypi.query_all([dep]))


def test_pypi_warns_about_old_pip(monkeypatch):
    monkeypatch.setattr(service.pypi, "_PIP_VERSION", Version("1.0.0"))
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(service.pypi, "logger", logger)

    # If we supply a cache directory, we're not relying on finding the `pip` cache so no need to log
    # a warning
    service.PyPIService(cache_dir)
    assert len(logger.warning.calls) == 0

    # However, if we're not specifying a cache directory, we'll try to call `pip cache dir`. If we
    # have an old `pip`, then we should expect a warning to be logged
    service.PyPIService()
    assert len(logger.warning.calls) == 1
