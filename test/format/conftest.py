from typing import Dict, List

import pytest
from packaging.version import Version

import pip_audit._fix as fix
import pip_audit._service as service

_RESOLVED_DEP_FOO = service.ResolvedDependency(name="foo", version=Version("1.0"))
_RESOLVED_DEP_BAR = service.ResolvedDependency(name="bar", version=Version("0.1"))
_SKIPPED_DEP = service.SkippedDependency(name="bar", skip_reason="skip-reason")

_TEST_VULN_DATA: Dict[service.Dependency, List[service.VulnerabilityResult]] = {
    _RESOLVED_DEP_FOO: [
        service.VulnerabilityResult(
            id="VULN-0",
            description="The first vulnerability",
            fix_versions=[
                Version("1.1"),
                Version("1.4"),
            ],
            aliases=set(),
        ),
        service.VulnerabilityResult(
            id="VULN-1",
            description="The second vulnerability",
            fix_versions=[Version("1.0")],
            aliases=set(),
        ),
    ],
    _RESOLVED_DEP_BAR: [
        service.VulnerabilityResult(
            id="VULN-2",
            description="The third vulnerability",
            fix_versions=[],
            aliases=set(),
        )
    ],
}

_TEST_VULN_DATA_SKIPPED_DEP: Dict[service.Dependency, List[service.VulnerabilityResult]] = {
    _RESOLVED_DEP_FOO: [
        service.VulnerabilityResult(
            id="VULN-0",
            description="The first vulnerability",
            fix_versions=[
                Version("1.1"),
                Version("1.4"),
            ],
            aliases=set(),
        ),
    ],
    _SKIPPED_DEP: [],
}

_TEST_NO_VULN_DATA: Dict[service.Dependency, List[service.VulnerabilityResult]] = {
    _RESOLVED_DEP_FOO: [],
    _RESOLVED_DEP_BAR: [],
}

_TEST_NO_VULN_DATA_SKIPPED_DEP: Dict[service.Dependency, List[service.VulnerabilityResult]] = {
    _RESOLVED_DEP_FOO: [],
    _RESOLVED_DEP_BAR: [],
    _SKIPPED_DEP: [],
}

_TEST_FIX_DATA: List[fix.FixVersion] = [
    fix.ResolvedFixVersion(dep=_RESOLVED_DEP_FOO, version=Version("1.8")),
    fix.ResolvedFixVersion(dep=_RESOLVED_DEP_BAR, version=Version("0.3")),
]

_TEST_SKIPPED_FIX_DATA: List[fix.FixVersion] = [
    fix.ResolvedFixVersion(dep=_RESOLVED_DEP_FOO, version=Version("1.8")),
    fix.SkippedFixVersion(dep=_RESOLVED_DEP_BAR, skip_reason="skip-reason"),
]


@pytest.fixture(autouse=True)
def vuln_data():
    return _TEST_VULN_DATA


@pytest.fixture(autouse=True)
def vuln_data_skipped_dep():
    return _TEST_VULN_DATA_SKIPPED_DEP


@pytest.fixture(autouse=True)
def no_vuln_data():
    return _TEST_NO_VULN_DATA


@pytest.fixture(autouse=True)
def no_vuln_data_skipped_dep():
    return _TEST_NO_VULN_DATA_SKIPPED_DEP


@pytest.fixture(autouse=True)
def fix_data():
    return _TEST_FIX_DATA


@pytest.fixture(autouse=True)
def skipped_fix_data():
    return _TEST_SKIPPED_FIX_DATA
