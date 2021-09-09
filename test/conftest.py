import pytest
from packaging.version import Version

from pip_audit.service.interface import Dependency, VulnerabilityResult, VulnerabilityService


@pytest.fixture(autouse=True)
def spec():
    def _spec(version):
        return Dependency(package="foo", version=Version(version))

    return _spec


@pytest.fixture(autouse=True)
def vuln_service():
    # A dummy service that only returns results for the "foo" package
    # between [1.0.0, 1.1.0).
    class Service(VulnerabilityService):
        def query(self, spec):
            introduced = Version("1.0.0")
            fixed = Version("1.1.0")

            if spec.package == "foo" and (introduced <= spec.version < fixed):
                return [
                    VulnerabilityResult(
                        id="fake-id",
                        description="this is not a real result",
                        version_introduced=Version("1.0.0"),
                        version_fixed=Version("1.1.0"),
                    )
                ]

            return []

    return Service
