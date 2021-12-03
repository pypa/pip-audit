from typing import Dict, List

import pytest
from packaging.version import Version

import pip_audit._service as service

_TEST_VULN_DATA: Dict[service.Dependency, List[service.VulnerabilityResult]] = {
    service.ResolvedDependency(name="foo", version=Version("1.0")): [
        service.VulnerabilityResult(
            id="VULN-0",
            description="The first vulnerability",
            fix_versions=[
                Version("1.1"),
                Version("1.4"),
            ],
        ),
        service.VulnerabilityResult(
            id="VULN-1",
            description="The second vulnerability",
            fix_versions=[Version("1.0")],
        ),
    ],
    service.ResolvedDependency(name="bar", version=Version("0.1")): [
        service.VulnerabilityResult(
            id="VULN-2",
            description="The third vulnerability",
            fix_versions=[],
        )
    ],
}

_TEST_VULN_DATA_SKIPPED_DEP: Dict[service.Dependency, List[service.VulnerabilityResult]] = {
    service.ResolvedDependency(name="foo", version=Version("1.0")): [
        service.VulnerabilityResult(
            id="VULN-0",
            description="The first vulnerability",
            fix_versions=[
                Version("1.1"),
                Version("1.4"),
            ],
        ),
    ],
    service.SkippedDependency(name="bar", skip_reason="skip-reason"): [],
}


@pytest.fixture(autouse=True)
def vuln_data():
    return _TEST_VULN_DATA


@pytest.fixture(autouse=True)
def vuln_data_skipped_dep():
    return _TEST_VULN_DATA_SKIPPED_DEP
