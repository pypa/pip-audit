from packaging.requirements import Requirement
from packaging.version import Version

from pip_audit.dependency_source import resolvelib
from pip_audit.service.interface import Dependency


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
    assert resolved_deps[req] == expected_deps


def test_resolvelib_marker_evaluate():
    pass
