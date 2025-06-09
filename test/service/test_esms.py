from __future__ import annotations

import random

import pretend  # type: ignore
import pytest
from packaging.version import Version
from requests.exceptions import ConnectTimeout, HTTPError

import pip_audit._service as service


def get_mock_session(func):
    class MockSession:
        def __init__(self, create_response):
            self.create_response = create_response

        def get(self, url, **kwargs):
            return self.create_response()

    return MockSession(func)


@pytest.mark.online
def test_esms():
    esms = service.EcosystemsService()
    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    results: dict[service.Dependency, list[service.VulnerabilityResult]] = dict(
        esms.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) > 0


@pytest.mark.online
def test_esms_version_ranges():
    # Try a package with vulnerabilities that have an explicitly stated introduced and fixed
    # version
    esms = service.EcosystemsService()
    dep = service.ResolvedDependency("ansible", Version("2.8.0"))
    results: dict[service.Dependency, list[service.VulnerabilityResult]] = dict(
        esms.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) > 0


@pytest.mark.online
def test_esms_multiple_pkg():
    esms = service.EcosystemsService()
    deps: list[service.Dependency] = [
        service.ResolvedDependency("jinja2", Version("2.4.1")),
        service.ResolvedDependency("flask", Version("0.5")),
    ]
    results: dict[service.Dependency, list[service.VulnerabilityResult]] = dict(
        esms.query_all(iter(deps))
    )

    assert len(results) == 2
    assert deps[0] in results and deps[1] in results

    assert len(results[deps[0]]) > 0
    assert len(results[deps[1]]) > 0


@pytest.mark.online
def test_esms_no_vuln():
    esms = service.EcosystemsService()
    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results: dict[service.Dependency, list[service.VulnerabilityResult]] = dict(
        esms.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0


def test_esms_connection_error(monkeypatch):
    esms = service.EcosystemsService()
    monkeypatch.setattr(esms.session, "get", pretend.raiser(ConnectTimeout))

    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    with pytest.raises(
        service.ConnectionError, match="Could not connect to ESMS' vulnerability feed"
    ):
        dict(esms.query_all(iter([dep])))


def test_esms_error_response(monkeypatch):
    def raise_for_status():
        raise HTTPError

    response = pretend.stub(raise_for_status=pretend.call_recorder(raise_for_status))
    get = pretend.call_recorder(lambda *a, **kw: response)

    esms = service.EcosystemsService()
    monkeypatch.setattr(esms.session, "get", get)

    dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
    with pytest.raises(service.ServiceError):
        dict(esms.query_all(iter([dep])))

    assert len(get.calls) == 1
    assert len(response.raise_for_status.calls) == 1


def test_esms_skipped_dep():
    esms = service.EcosystemsService()
    dep = service.SkippedDependency(name="foo", skip_reason="skip-reason")
    results: dict[service.Dependency, list[service.VulnerabilityResult]] = dict(
        esms.query_all(iter([dep]))
    )

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0


@pytest.mark.parametrize("_n", range(10))
def test_esms_id_sort(monkeypatch, _n):
    ids = ["fakeid", "fake-id-2", "CVE-XXXX-XXXXX", "PYSEC-XXXX-XXXXX", "GHSA-foo-bar-baz"]
    random.shuffle(ids)

    payload = [
        {
            "identifiers": ids,
            "title": "title",
            "description": "description",
            "withdrawn_at": None,
            "packages": [
                {
                    "package_name": "foo",
                    "ecosystem": "pypi",
                    "versions": [
                        {"first_patched_version": "1.0.1", "vulnerable_version_range": "< 1.0.1"}
                    ],
                }
            ],
        }
    ]

    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    get = pretend.call_recorder(lambda *a, **kw: response)

    esms = service.EcosystemsService()
    monkeypatch.setattr(esms.session, "get", get)

    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results = dict(esms.query_all(iter([dep])))

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 1

    assert vulns[0].id == "PYSEC-XXXX-XXXXX"
    for id in ids:
        if id != "PYSEC-XXXX-XXXXX":
            assert id in vulns[0].aliases


def test_esms_ecosystem_not_pypi(monkeypatch):
    payload = [
        {
            "identifiers": ["fakeid"],
            "title": "title",
            "description": "description",
            "withdrawn_at": None,
            "packages": [
                {
                    "package_name": "foo",
                    "ecosystem": "notpypi",
                    "versions": [
                        {"first_patched_version": "1.0.1", "vulnerable_version_range": "< 1.0.1"}
                    ],
                }
            ],
        }
    ]

    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    get = pretend.call_recorder(lambda *a, **kw: response)

    esms = service.EcosystemsService()
    monkeypatch.setattr(esms.session, "get", get)

    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results = dict(esms.query_all(iter([dep])))

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0


@pytest.mark.parametrize(
    ["title", "description", "out_description"],
    [
        ("fakesummary", "fakedetails", "fakesummary"),
        ("fakesummary\nanother line", "fakedetails", "fakesummary another line"),
        (None, "fakedetails", "fakedetails"),
        (None, "fakedetails\nanother line", "fakedetails another line"),
        (None, None, "N/A"),
    ],
)
def test_esms_vuln_description_fallbacks(monkeypatch, title, description, out_description):
    payload = [
        {
            "identifiers": ["fakeid"],
            "title": title,
            "description": description,
            "withdrawn_at": None,
            "packages": [
                {
                    "package_name": "foo",
                    "ecosystem": "pypi",
                    "versions": [
                        {"first_patched_version": "1.0.1", "vulnerable_version_range": "< 1.0.1"}
                    ],
                }
            ],
        }
    ]

    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    get = pretend.call_recorder(lambda *a, **kw: response)

    esms = service.EcosystemsService()
    monkeypatch.setattr(esms.session, "get", get)

    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results = dict(esms.query_all(iter([dep])))

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 1

    assert vulns[0].description == out_description


def test_esms_vuln_withdrawn(monkeypatch):
    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(service.esms, "logger", logger)

    payload = [
        {
            "identifiers": ["fakeid"],
            "title": "faketitle",
            "description": "fakedescription",
            "withdrawn_at": "some-datetime",
            "packages": [
                {
                    "package_name": "foo",
                    "ecosystem": "pypi",
                    "versions": [
                        {"first_patched_version": "1.0.1", "vulnerable_version_range": "< 1.0.1"}
                    ],
                }
            ],
        }
    ]

    response = pretend.stub(raise_for_status=lambda: None, json=lambda: payload)
    get = pretend.call_recorder(lambda *a, **kw: response)

    esms = service.EcosystemsService()
    monkeypatch.setattr(esms.session, "get", get)

    dep = service.ResolvedDependency("foo", Version("1.0.0"))
    results = dict(esms.query_all(iter([dep])))

    assert len(results) == 1
    assert dep in results

    vulns = results[dep]
    assert len(vulns) == 0

    assert logger.debug.calls == [
        pretend.call("ESMS vuln entry 'fakeid' marked as withdrawn at some-datetime")
    ]
