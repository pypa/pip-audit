from typing import Dict, List

from packaging.version import Version

from pip_audit._fix import ResolvedFixVersion, SkippedFixVersion, resolve_fix_versions
from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityResult,
)


def test_fix(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: Dict[Dependency, List[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=[Version("1.0.0")],
                aliases=set(),
            )
        ]
    }
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert len(fix_versions) == 1
    assert fix_versions[0] == ResolvedFixVersion(dep=dep, version=Version("1.1.0"))
    assert not fix_versions[0].is_skipped()


def test_fix_skipped_deps(vuln_service):
    dep = SkippedDependency(name="foo", skip_reason="skip-reason")
    result: Dict[Dependency, List[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=[Version("1.0.0")],
                aliases=set(),
            )
        ]
    }
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert not fix_versions


def test_fix_no_vulns(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: Dict[Dependency, List[VulnerabilityResult]] = {dep: list()}
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert not fix_versions


def test_fix_resolution_impossible(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: Dict[Dependency, List[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=list(),
                aliases=set(),
            )
        ]
    }
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert len(fix_versions) == 1
    assert fix_versions[0] == SkippedFixVersion(
        dep=dep,
        skip_reason="failed to fix dependency foo (0.5.0), unable to find fix version for "
        "vulnerability fake-id",
    )
    assert fix_versions[0].is_skipped()
