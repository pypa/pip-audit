from typing import Dict, List

import pytest
from packaging.version import Version

import pip_audit.service as service

_TEST_VULN_DATA: Dict[service.Dependency, List[service.VulnerabilityResult]] = {
    service.Dependency(package="foo", version="1.0"): [
        service.VulnerabilityResult(
            id="VULN-0",
            description="The first vulnerability",
            version_range=[
                service.VersionRange(introduced=Version("0.9"), fixed=Version("1.1")),
                service.VersionRange(introduced=None, fixed=Version("1.4")),
            ],
        ),
        service.VulnerabilityResult(
            id="VULN-1",
            description="The second vulnerability",
            version_range=[service.VersionRange(introduced=Version("0.5"), fixed=Version("1.0"))],
        ),
    ],
    service.Dependency(package="bar", version="0.1"): [
        service.VulnerabilityResult(
            id="VULN-2",
            description="The third vulnerability",
            version_range=[service.VersionRange(introduced=Version("0.1"), fixed=None)],
        )
    ],
}


@pytest.fixture(autouse=True)
def vuln_data():
    return _TEST_VULN_DATA
