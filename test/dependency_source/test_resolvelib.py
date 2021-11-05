from email.message import EmailMessage
from typing import List

import pytest
import requests
from packaging.requirements import Requirement
from packaging.version import Version
from requests.exceptions import HTTPError
from resolvelib.resolvers import InconsistentCandidate, ResolutionImpossible

from pip_audit.dependency_source import resolvelib
from pip_audit.dependency_source.resolvelib import pypi_provider
from pip_audit.service.interface import Dependency


def get_package_mock(data):
    class Doc:
        def __init__(self, content):
            self.content = content

        def raise_for_status(self):
            pass

    return Doc(data)


def get_metadata_mock():
    return EmailMessage()


def check_deps(resolved_deps: List[Dependency], expected_deps: List[Dependency]):
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


def test_resolvelib():
    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    resolved_deps = dict(resolver.resolve_all([req]))
    assert len(resolved_deps) == 1
    expected_deps = [
        Dependency("flask", Version("2.0.1")),
        Dependency("werkzeug", Version("2.0.1")),
        Dependency("jinja2", Version("3.0.1")),
        Dependency("itsdangerous", Version("2.0.1")),
        Dependency("click", Version("8.0.1")),
        Dependency("markupsafe", Version("2.0.1")),
    ]
    assert req in resolved_deps
    # Earlier Python versions have some extra dependencies. To avoid conditionals here, let's just
    # check that the dependencies we specify are a subset.
    check_deps(resolved_deps[req], expected_deps)


def test_resolvelib_extras():
    resolver = resolvelib.ResolveLibResolver()

    # First check the dependencies without extras and as a basis for comparison
    req = Requirement("requests>=2.8.1")
    resolved_deps = dict(resolver.resolve_all([req]))
    assert len(resolved_deps) == 1
    expected_deps = [
        Dependency("requests", Version("2.26.0")),
        Dependency("charset-normalizer", Version("2.0.6")),
        Dependency("idna", Version("3.2")),
        Dependency("certifi", Version("2021.5.30")),
        Dependency("urllib3", Version("1.26.7")),
    ]
    assert req in resolved_deps
    check_deps(resolved_deps[req], expected_deps)

    # Check that using the `socks` and `use_chardet_on_py3` extras pulls in additional dependencies
    req = Requirement("requests[socks,use_chardet_on_py3]>=2.8.1")
    resolved_deps = dict(resolver.resolve_all([req]))
    assert len(resolved_deps) == 1
    expected_deps.extend(
        [Dependency("chardet", Version("4.0.0")), Dependency("pysocks", Version("1.7.1"))]
    )
    assert req in resolved_deps
    check_deps(resolved_deps[req], expected_deps)


def test_resolvelib_sdist():
    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("ansible-core==2.11.5")
    resolved_deps = dict(resolver.resolve_all([req]))
    assert len(resolved_deps) == 1
    expected_deps = [
        Dependency("ansible-core", Version("2.11.5")),
        Dependency("pyparsing", Version("2.4.7")),
        Dependency("jinja2", Version("3.0.1")),
        Dependency("pycparser", Version("2.20")),
        Dependency("pyyaml", Version("5.4.1")),
        Dependency("cffi", Version("1.14.6")),
        Dependency("resolvelib", Version("0.5.4")),
        Dependency("packaging", Version("21.0")),
        Dependency("cryptography", Version("35.0.0")),
        Dependency("markupsafe", Version("2.0.1")),
    ]
    assert req in resolved_deps
    check_deps(resolved_deps[req], expected_deps)


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

    monkeypatch.setattr(requests, "get", lambda _: get_package_mock(data))
    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    resolved_deps = dict(resolver.resolve_all([req]))
    assert req in resolved_deps
    assert resolved_deps[req] == [Dependency("flask", Version("2.0.1"))]


# Source distributions can be either zipped or tarballed.
@pytest.mark.parametrize("suffix", ["tar.gz", "zip"])
def test_resolvelib_sdist_patched(monkeypatch, suffix):
    # In the following unit tests, we'll be mocking certain function calls to test corner cases in
    # the resolver. Before doing that, use the mocks to exercise the happy path to ensure that
    # everything works end-to-end.
    data = f'<a href="https://example.com/Flask-2.0.1.{suffix}">Flask-2.0.1.{suffix}</a><br/>'

    monkeypatch.setattr(requests, "get", lambda _: get_package_mock(data))
    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_sdist", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    resolved_deps = dict(resolver.resolve_all([req]))
    assert req in resolved_deps
    assert resolved_deps[req] == [Dependency("flask", Version("2.0.1"))]


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

    monkeypatch.setattr(requests, "get", lambda _: get_package_mock(data))

    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    with pytest.raises(ResolutionImpossible):
        dict(resolver.resolve_all([req]))


def test_resolvelib_wheel_canonical_name_mismatch(monkeypatch):
    # Call the underlying wheel, Mask instead of Flask. This should throw an `InconsistentCandidate`
    # error.
    data = (
        '<a href="https://files.pythonhosted.org/packages/54/4f/'
        "1b294c1a4ab7b2ad5ca5fc4a9a65a22ef1ac48be126289d97668852d4ab3/Mask-2.0.1-py3-none-any.whl#"
        'sha256=a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9">'
        "Mask-2.0.1-py3-none-any.whl</a><br/>"
    )

    monkeypatch.setattr(requests, "get", lambda _: get_package_mock(data))
    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    with pytest.raises(InconsistentCandidate):
        dict(resolver.resolve_all([req]))


def test_resolvelib_wheel_invalid_version(monkeypatch):
    # Give the wheel an invalid version name like `INVALID.VERSION` and ensure that it gets skipped
    # over.
    data = (
        '<a href="https://files.pythonhosted.org/packages/54/4f/'
        "1b294c1a4ab7b2ad5ca5fc4a9a65a22ef1ac48be126289d97668852d4ab3/Flask-INVALID.VERSION-py3-"
        'none-any.whl#sha256=a6209ca15eb63fc9385f38e452704113d679511d9574d09b2cf9183ae7d20dc9">'
        "Flask-INVALID.VERSION-py3-none-any.whl</a><br/>"
    )

    monkeypatch.setattr(requests, "get", lambda _: get_package_mock(data))
    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    with pytest.raises(ResolutionImpossible):
        dict(resolver.resolve_all([req]))


def test_resolvelib_sdist_invalid_suffix(monkeypatch):
    # Give the sdist an invalid suffix like ".foo" and insure that it gets skipped.
    data = '<a href="https://example.com/Flask-2.0.1.foo">Flask-2.0.1.foo</a><br/>'

    monkeypatch.setattr(requests, "get", lambda _: get_package_mock(data))
    monkeypatch.setattr(
        pypi_provider.Candidate, "_get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    with pytest.raises(ResolutionImpossible):
        dict(resolver.resolve_all([req]))


def test_resolvelib_http_error(monkeypatch):
    def get_http_error_mock():
        class Doc:
            def raise_for_status(self):
                raise HTTPError

        return Doc()

    monkeypatch.setattr(requests, "get", lambda _: get_http_error_mock())

    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    with pytest.raises(resolvelib.ResolveLibResolverError):
        dict(resolver.resolve_all([req]))
