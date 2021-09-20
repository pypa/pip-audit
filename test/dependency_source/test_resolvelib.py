from packaging.requirements import Requirement

from pip_audit.dependency_source import resolvelib


def test_resolvelib():
    resolver = resolvelib.ResolveLibResolver()
    reqs = [Requirement("flask==2.0.1")]
    resolved_deps = dict(resolver.resolve_all(reqs))
    print(resolved_deps)
