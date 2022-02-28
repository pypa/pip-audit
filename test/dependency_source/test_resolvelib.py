from email.message import EmailMessage
from typing import List

import pytest
import requests
from packaging.requirements import Requirement
from packaging.version import Version
from pip_api import Requirement as ParsedRequirement
from requests.exceptions import HTTPError
from resolvelib.resolvers import InconsistentCandidate, ResolutionImpossible

from pip_audit._dependency_source import resolvelib
from pip_audit._dependency_source.resolvelib import pypi_provider
from pip_audit._service.interface import ResolvedDependency, SkippedDependency


def get_package_mock(data):
    class Doc:
        def __init__(self, content):
            self.content = content
            self.status_code = 200

        def raise_for_status(self):
            pass

    return Doc(data)


def get_metadata_mock():
    return EmailMessage()


def check_deps(resolved_deps: List[ResolvedDependency], expected_deps: List[ResolvedDependency]):
    # We don't want to just check that the two lists are equal because:
    # - Some packages install additional dependencies for specific versions of Python. It's only
    #   practical to check that the resolved dependencies contain all the expected ones (but there
    #   may be more and that's ok).
    # - A common pattern is for packages to pin a minimum version for a dependency. This means that
    #   the exact resolved version of a dependency will change when new versions of it are
    #   published. Therefore, our check should make sure that the resolved version is greater than
    #   or equal to the expected version.
    for expected in expected_deps:
        found = False
        for resolved in resolved_deps:
            if expected.name == resolved.name and expected.version <= resolved.version:
                found = True
                break
        assert found


@pytest.mark.online
def test_resolvelib():
    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert len(resolved_deps) == 1
    expected_deps = [
        ResolvedDependency("flask", Version("2.0.1")),
        ResolvedDependency("werkzeug", Version("2.0.1")),
        ResolvedDependency("jinja2", Version("3.0.1")),
        ResolvedDependency("itsdangerous", Version("2.0.1")),
        ResolvedDependency("click", Version("8.0.1")),
        ResolvedDependency("markupsafe", Version("2.0.1")),
    ]
    assert req in resolved_deps
    # Earlier Python versions have some extra dependencies. To avoid conditionals here, let's just
    # check that the dependencies we specify are a subset.
    check_deps(resolved_deps[req], expected_deps)  # type: ignore


@pytest.mark.online
def test_resolvelib_extras():
    resolver = resolvelib.ResolveLibResolver()

    # First check the dependencies without extras and as a basis for comparison
    req = Requirement("requests>=2.8.1")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert len(resolved_deps) == 1
    expected_deps = [
        ResolvedDependency("requests", Version("2.26.0")),
        ResolvedDependency("charset-normalizer", Version("2.0.6")),
        ResolvedDependency("idna", Version("3.2")),
        ResolvedDependency("certifi", Version("2021.5.30")),
        ResolvedDependency("urllib3", Version("1.26.7")),
    ]
    assert req in resolved_deps
    check_deps(resolved_deps[req], expected_deps)  # type: ignore

    # Check that using the `socks` and `use_chardet_on_py3` extras pulls in additional dependencies
    req = Requirement("requests[socks,use_chardet_on_py3]>=2.8.1")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert len(resolved_deps) == 1
    expected_deps.extend(
        [
            ResolvedDependency("chardet", Version("4.0.0")),
            ResolvedDependency("pysocks", Version("1.7.1")),
        ]
    )
    assert req in resolved_deps
    check_deps(resolved_deps[req], expected_deps)  # type: ignore


@pytest.mark.online
def test_resolvelib_sdist():
    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("ansible-core==2.11.5")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert len(resolved_deps) == 1
    expected_deps = [
        ResolvedDependency("ansible-core", Version("2.11.5")),
        ResolvedDependency("pyparsing", Version("2.4.7")),
        ResolvedDependency("jinja2", Version("3.0.1")),
        ResolvedDependency("pycparser", Version("2.20")),
        ResolvedDependency("pyyaml", Version("5.4.1")),
        ResolvedDependency("cffi", Version("1.14.6")),
        ResolvedDependency("resolvelib", Version("0.5.4")),
        ResolvedDependency("packaging", Version("21.0")),
        ResolvedDependency("cryptography", Version("35.0.0")),
        ResolvedDependency("markupsafe", Version("2.0.1")),
    ]
    assert req in resolved_deps
    check_deps(resolved_deps[req], expected_deps)  # type: ignore


def test_resolvelib_wheel_patched(monkeypatch):
    # In the following unit tests, we'll be mocking certain function calls to test corner cases in
    # the resolver. Before doing that, use the mocks to exercise the happy path to ensure that
    # everything works end-to-end.
    data = (
        '<a href="https://files.pythonhosted.org/packages/54/4f/'
        "1b294c1a4ab7b2ad5ca5fc4a9a65a22ef1ac48be126289d97668852d4ab3/Flask-2.0.1-py3-none-any.whl#"
        'sha256=a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9">'
        "Flask-2.0.1-py3-none-any.whl</a><br/>"
    )

    # monkeypatch.setattr(requests, "get", lambda _url, **kwargs: get_package_mock(data))
    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    monkeypatch.setattr(
        resolver.provider.session, "get", lambda _url, **kwargs: get_package_mock(data)
    )

    req = Requirement("flask==2.0.1")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert req in resolved_deps
    assert resolved_deps[req] == [ResolvedDependency("flask", Version("2.0.1"))]


# Source distributions can be either zipped or tarballed.
@pytest.mark.parametrize("suffix", ["tar.gz", "zip"])
def test_resolvelib_sdist_patched(monkeypatch, suffix):
    # In the following unit tests, we'll be mocking certain function calls to test corner cases in
    # the resolver. Before doing that, use the mocks to exercise the happy path to ensure that
    # everything works end-to-end.
    data = f'<a href="https://example.com/Flask-2.0.1.{suffix}">Flask-2.0.1.{suffix}</a><br/>'

    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_sdist", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    monkeypatch.setattr(
        resolver.provider.session, "get", lambda _url, **kwargs: get_package_mock(data)
    )

    req = Requirement("flask==2.0.1")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert req in resolved_deps
    assert resolved_deps[req] == [ResolvedDependency("flask", Version("2.0.1"))]


def test_resolvelib_wheel_python_version(monkeypatch):
    # Some versions stipulate a particular Python version and should be skipped by the provider.
    # Since `pip-audit` doesn't support Python 2.7, the Flask version below should always be skipped
    # and the resolver should be unable to find dependencies.
    data = (
        '<a href="https://files.pythonhosted.org/packages/54/4f/'
        "1b294c1a4ab7b2ad5ca5fc4a9a65a22ef1ac48be126289d97668852d4ab3/Flask-2.0.1-py3-none-any.whl#"
        'sha256=a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9" '
        'data-requires-python="&lt;=2.7">Flask-2.0.1-py3-none-any.whl</a><br/>'
    )

    resolver = resolvelib.ResolveLibResolver()
    monkeypatch.setattr(
        resolver.provider.session, "get", lambda _url, **kwargs: get_package_mock(data)
    )

    req = Requirement("flask==2.0.1")
    with pytest.raises(ResolutionImpossible):
        dict(resolver.resolve_all(iter([req])))


def test_resolvelib_wheel_canonical_name_mismatch(monkeypatch):
    # Call the underlying wheel, Mask instead of Flask. This should throw an `InconsistentCandidate`
    # error.
    data = (
        '<a href="https://files.pythonhosted.org/packages/54/4f/'
        "1b294c1a4ab7b2ad5ca5fc4a9a65a22ef1ac48be126289d97668852d4ab3/Mask-2.0.1-py3-none-any.whl#"
        'sha256=a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9">'
        "Mask-2.0.1-py3-none-any.whl</a><br/>"
    )

    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    monkeypatch.setattr(
        resolver.provider.session, "get", lambda _url, **kwargs: get_package_mock(data)
    )

    req = Requirement("flask==2.0.1")
    with pytest.raises(InconsistentCandidate):
        dict(resolver.resolve_all(iter([req])))


def test_resolvelib_wheel_invalid_version(monkeypatch):
    # Give the wheel an invalid version name like `INVALID.VERSION` and ensure that it gets skipped
    # over.
    data = (
        '<a href="https://files.pythonhosted.org/packages/54/4f/'
        "1b294c1a4ab7b2ad5ca5fc4a9a65a22ef1ac48be126289d97668852d4ab3/Flask-INVALID.VERSION-py3-"
        'none-any.whl#sha256=a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9">'
        "Flask-INVALID.VERSION-py3-none-any.whl</a><br/>"
    )

    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    monkeypatch.setattr(
        resolver.provider.session, "get", lambda _url, **kwargs: get_package_mock(data)
    )

    req = Requirement("flask==2.0.1")
    with pytest.raises(ResolutionImpossible):
        dict(resolver.resolve_all(iter([req])))


def test_resolvelib_sdist_invalid_suffix(monkeypatch):
    # Give the sdist an invalid suffix like ".foo" and insure that it gets skipped.
    data = '<a href="https://example.com/Flask-2.0.1.foo">Flask-2.0.1.foo</a><br/>'

    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    monkeypatch.setattr(
        resolver.provider.session, "get", lambda _url, **kwargs: get_package_mock(data)
    )

    req = Requirement("flask==2.0.1")
    with pytest.raises(ResolutionImpossible):
        dict(resolver.resolve_all(iter([req])))


def test_resolvelib_http_error(monkeypatch):
    def get_http_error_mock():
        class Doc:
            def __init__(self):
                self.status_code = 400

            def raise_for_status(self):
                raise HTTPError

        return Doc()

    monkeypatch.setattr(requests, "get", lambda _url, **kwargs: get_http_error_mock())

    resolver = resolvelib.ResolveLibResolver()
    monkeypatch.setattr(
        resolver.provider.session, "get", lambda _url, **kwargs: get_http_error_mock()
    )

    req = Requirement("flask==2.0.1")
    with pytest.raises(resolvelib.ResolveLibResolverError):
        dict(resolver.resolve_all(iter([req])))


def test_resolvelib_http_notfound(monkeypatch):
    def get_http_not_found_mock():
        class Doc:
            def __init__(self):
                self.status_code = 404

        return Doc()

    resolver = resolvelib.ResolveLibResolver()
    monkeypatch.setattr(
        resolver.provider.session, "get", lambda _url, **kwargs: get_http_not_found_mock()
    )

    req = Requirement("flask==2.0.1")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert len(resolved_deps) == 1
    expected_deps = [
        SkippedDependency(
            name="flask",
            skip_reason='Could not find project "flask" on any of the supplied index URLs: '
            "['https://pypi.org/simple']",
        )
    ]
    assert req in resolved_deps
    assert resolved_deps[req] == expected_deps


def test_resolvelib_multiple_indexes(monkeypatch):
    url1 = "https://index1"
    url2 = "https://index2"
    package_url1 = f"{url1}/flask"
    package_url2 = f"{url2}/flask"
    data1 = (
        '<a href="https://files.pythonhosted.org/packages/d4/6a/'
        "93500f2a7089b4e993fb095215979890b6204a5ba3f6b0f63dc6c3c6c827/Flask-0.5.tar.gz#"
        'sha256=20e176b1db0e2bfe92d869f7b5d0ee3e5d6cb60e793755aaf2284bd78a6202ea">Flask-0.5.tar.gz'
        "</a><br/>"
    )
    data2 = (
        '<a href="https://files.pythonhosted.org/packages/44/86/'
        "481371798994529e105633a50b2332638105a1e191053bc0f4bbc9b91791/Flask-0.6.tar.gz#"
        'sha256=9dc18a7c673bf0a6fada51e011fc411285a8301f6dfc1c000ebfa272b5e609e4">Flask-0.6.tar.gz'
        "</a><br/>"
    )

    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_sdist", lambda _: get_metadata_mock()
    )

    def get_multiple_index_package_mock(url):
        if url == package_url1:
            return get_package_mock(data1)
        else:
            assert url == package_url2
            return get_package_mock(data2)

    resolver = resolvelib.ResolveLibResolver([url1, url2])
    monkeypatch.setattr(
        resolver.provider.session, "get", lambda url, **kwargs: get_multiple_index_package_mock(url)
    )

    # We want to check that dependency resolution is considering packages found on both indexes
    #
    # Test with a requirement that will resolve to a package on the first index
    req = Requirement("flask<=0.5")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert req in resolved_deps
    assert resolved_deps[req] == [ResolvedDependency("flask", Version("0.5"))]

    # Now test with a requirement that will resolve to a package on the second index
    req = Requirement("flask<=0.6")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert req in resolved_deps
    assert resolved_deps[req] == [ResolvedDependency("flask", Version("0.6"))]


def test_resolvelib_package_missing_on_one_index(monkeypatch):
    url1 = "https://index1"
    url2 = "https://index2"
    package_url1 = f"{url1}/flask"
    package_url2 = f"{url2}/flask"
    data1 = (
        '<a href="https://files.pythonhosted.org/packages/d4/6a/'
        "93500f2a7089b4e993fb095215979890b6204a5ba3f6b0f63dc6c3c6c827/Flask-0.5.tar.gz#"
        'sha256=20e176b1db0e2bfe92d869f7b5d0ee3e5d6cb60e793755aaf2284bd78a6202ea">Flask-0.5.tar.gz'
        "</a><br/>"
    )

    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_sdist", lambda _: get_metadata_mock()
    )

    # Simulate the package not existing on the second index
    def get_multiple_index_package_mock(url):
        if url == package_url1:
            return get_package_mock(data1)
        else:
            assert url == package_url2
            pkg = get_package_mock(str())
            pkg.status_code = 404
            return pkg

    resolver = resolvelib.ResolveLibResolver([url1, url2])
    monkeypatch.setattr(
        resolver.provider.session, "get", lambda url, **kwargs: get_multiple_index_package_mock(url)
    )

    # If a package doesn't exist on one index, we shouldn't expect an error. We should just skip it
    # and only use the other index for finding candidates.
    req = Requirement("flask<=0.5")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert req in resolved_deps
    assert resolved_deps[req] == [ResolvedDependency("flask", Version("0.5"))]

    # Now test with a requirement that will resolve to a package on the second index
    req = Requirement("flask<=0.6")
    resolved_deps = dict(resolver.resolve_all(iter([req])))
    assert req in resolved_deps
    assert resolved_deps[req] == [ResolvedDependency("flask", Version("0.5"))]


def test_resolvelib_skip_editable():
    resolver = resolvelib.ResolveLibResolver(skip_editable=True)
    req = ParsedRequirement("foo==1.0.0", editable=True, filename="stub", lineno=1)

    deps = resolver.resolve(req)  # type: ignore
    assert len(deps) == 1
    assert deps[0] == SkippedDependency(name="foo", skip_reason="requirement marked as editable")
