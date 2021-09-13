from pip_audit.service.interface import Dependency


def test_dependency_source(dep_source):
    source = dep_source()

    for spec in source.collect():
        assert isinstance(spec, Dependency)
