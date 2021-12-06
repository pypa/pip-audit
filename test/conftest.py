import tempfile

import pytest
from packaging.version import Version

from pip_audit._dependency_source.interface import DependencySource
from pip_audit._service.interface import (
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)


@pytest.fixture(autouse=True)
def spec():
    def _spec(version):
        return ResolvedDependency(name="foo", version=Version(version))

    return _spec


@pytest.fixture(autouse=True)
def vuln_service():
    # A dummy service that only returns results for the "foo" package
    # between [1.0.0, 1.1.0).
    class Service(VulnerabilityService):
        def query(self, spec):
            introduced = Version("1.0.0")
            fixed = Version("1.1.0")

            if spec.name == "foo" and (introduced <= spec.version < fixed):
                return spec, [
                    VulnerabilityResult(
                        id="fake-id",
                        description="this is not a real result",
                        fix_versions=[fixed],
                    )
                ]

            return spec, []

    return Service


@pytest.fixture(autouse=True)
def dep_source(spec):
    class Source(DependencySource):
        def collect(self):
            yield spec("1.0.1")

    return Source


@pytest.fixture(scope="session")
def cache_dir():
    cache = tempfile.TemporaryDirectory()
    yield cache.name
    cache.cleanup()
