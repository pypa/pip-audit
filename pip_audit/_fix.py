"""
Resolving fix versions.
"""

from typing import Dict, Iterator, List, Tuple, cast

from packaging.version import Version

from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)


def resolve_fix_versions(
    service: VulnerabilityService, result: Dict[Dependency, List[VulnerabilityResult]]
) -> Iterator[Tuple[ResolvedDependency, Version]]:
    for (dep, vulns) in result.items():
        if dep.is_skipped():
            continue
        if not vulns:
            continue
        dep = cast(ResolvedDependency, dep)
        yield (dep, _resolve_fix_version(service, dep, vulns))


def _resolve_fix_version(
    service: VulnerabilityService, dep: ResolvedDependency, vulns: List[VulnerabilityResult]
) -> Version:
    # We need to upgrade to a fix version that satisfies all vulnerability results
    #
    # However, whenever we upgrade a dependency, we run the risk of introducing new vulnerabilities
    # so we need to run this in a loop and continue polling the vulnerability service on each
    # prospective resolved fix version
    current_version = dep.version
    current_vulns = vulns
    while current_vulns:

        def get_earliest_fix_version(fix_versions: List[Version]) -> Version:
            for v in fix_versions:
                if v > current_version:
                    return v
            raise RuntimeError

        # We want to retrieve a version that potentially fixes all vulnerabilities
        current_version = max(
            [get_earliest_fix_version(v.fix_versions) for v in current_vulns if v.fix_versions]
        )
        _, current_vulns = service.query(ResolvedDependency(dep.name, current_version))
    return current_version
