from email.message import EmailMessage

import pytest
import requests
from packaging.requirements import Requirement
from packaging.version import Version
from resolvelib.resolvers import InconsistentCandidate, ResolutionImpossible

from pip_audit.dependency_source import resolvelib
from pip_audit.dependency_source.resolvelib import pypi_wheel_provider
from pip_audit.service.interface import Dependency


def get_package_mock(data):
    class Doc:
        def __init__(self, content):
            self.content = content

    return Doc(data)


def get_metadata_mock():
    return EmailMessage()


def test_resolvelib():
    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    resolved_deps = dict(resolver.resolve_all([req]))
    assert len(resolved_deps) == 1
    expected_deps = set(
        [
            Dependency("flask", Version("2.0.1")),
            Dependency("werkzeug", Version("2.0.1")),
            Dependency("jinja2", Version("3.0.1")),
            Dependency("itsdangerous", Version("2.0.1")),
            Dependency("click", Version("8.0.1")),
            Dependency("markupsafe", Version("2.0.1")),
        ]
    )
    assert req in resolved_deps
    # Earlier Python versions have some extra dependencies. To avoid conditionals here, let's just
    # check that the dependencies we specify are a subset.
    assert expected_deps.issubset(resolved_deps[req])


def test_resolvelib_extras():
    # TODO(alex): The resolver currently doesn't support extras
    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("requests[security,tests]>=2.8.1")
    with pytest.raises(AssertionError, match="extras not supported"):
        dict(resolver.resolve_all([req]))


def test_resolvelib_patched(monkeypatch):
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
        pypi_wheel_provider, "get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    resolved_deps = dict(resolver.resolve_all([req]))
    assert req in resolved_deps
    assert resolved_deps[req] == [Dependency("flask", Version("2.0.1"))]


def test_resolvelib_python_version(monkeypatch):
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


def test_resolvelib_canonical_name_mismatch(monkeypatch):
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
        pypi_wheel_provider, "get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    with pytest.raises(InconsistentCandidate):
        dict(resolver.resolve_all([req]))


def test_resolvelib_invalid_version(monkeypatch):
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
        pypi_wheel_provider, "get_metadata_for_wheel", lambda _: get_metadata_mock()
    )

    resolver = resolvelib.ResolveLibResolver()
    req = Requirement("flask==2.0.1")
    with pytest.raises(ResolutionImpossible):
        dict(resolver.resolve_all([req]))
