"""
Functionality for using the [OSV](https://osv.dev/) API as a `VulnerabilityService`.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, cast

import requests
from packaging.version import Version

from pip_audit._cache import caching_session
from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    ServiceError,
    VulnerabilityResult,
    VulnerabilityService,
)


class OsvService(VulnerabilityService):
    """
    An implementation of `VulnerabilityService` that uses OSV to provide Python
    package vulnerability information.
    """

    def __init__(self, cache_dir: Optional[Path] = None, timeout: Optional[int] = None):
        """
        Create a new `OsvService`.

        `cache_dir` is an optional cache directory to use, for caching and reusing OSV API
        requests. If `None`, `pip-audit` will use its own internal caching directory.

        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.
        """
        self.session = caching_session(cache_dir, use_pip=False)
        self.timeout = timeout

    def query(self, spec: Dependency) -> Tuple[Dependency, List[VulnerabilityResult]]:
        """
        Queries OSV for the given `Dependency` specification.

        See `VulnerabilityService.query`.
        """
        if spec.is_skipped():
            return spec, []
        spec = cast(ResolvedDependency, spec)

        url = "https://api.osv.dev/v1/query"
        query = {
            "package": {"name": spec.canonical_name, "ecosystem": "PyPI"},
            "version": str(spec.version),
        }
        response: requests.Response = self.session.post(
            url=url,
            data=json.dumps(query),
            timeout=self.timeout,
        )

        results: List[VulnerabilityResult] = []

        # Check for an unsuccessful status code
        try:
            response.raise_for_status()
        except requests.HTTPError as http_error:
            raise ServiceError from http_error

        # If the response is empty, that means that the package/version pair doesn't have any
        # associated vulnerabilities
        #
        # In that case, return an empty list
        response_json = response.json()
        if not response_json:
            return spec, results

        # We reduce the list of vulnerabilities down according to the following rules:
        # 1. If a vulnerability shares an alias with any other vulnerability, then
        #    we only emit it once.
        # 2. We prefer vulnerabilities with PYSEC IDs whenever possible.
        vulns = response_json["vulns"]

        # First pass: unique and add all PYSEC vulnerabilities first.
        unique_vulns: List[Dict[str, Any]] = []
        seen_aliases: Set[str] = set()
        for v in vulns:
            if not v["id"].startswith("PYSEC"):
                continue

            if seen_aliases.intersection(set(v["aliases"])):
                continue

            seen_aliases.update(v["aliases"])
            unique_vulns.append(v)

        # Second pass: add any non-PYSEC vulnerabilities.
        for v in vulns:
            if seen_aliases.intersection(set(v["aliases"])):
                continue

            seen_aliases.update(v["aliases"])
            unique_vulns.append(v)

        for vuln in unique_vulns:
            id = vuln["id"]
            description = vuln["details"]
            aliases = vuln["aliases"]
            fix_versions: List[Version] = []
            for affected in vuln["affected"]:
                pkg = affected["package"]
                # We only care about PyPI versions
                if pkg["name"] == spec.canonical_name and pkg["ecosystem"] == "PyPI":
                    for ranges in affected["ranges"]:
                        if ranges["type"] == "ECOSYSTEM":
                            # Filter out non-fix versions
                            fix_version_strs = [
                                version["fixed"]
                                for version in ranges["events"]
                                if "fixed" in version
                            ]
                            # Convert them to version objects
                            fix_versions = [
                                Version(version_str) for version_str in fix_version_strs
                            ]
                            break

            # The ranges aren't guaranteed to come in chronological order
            fix_versions.sort()

            results.append(VulnerabilityResult(id, description, fix_versions, aliases))

        #

        return spec, results
