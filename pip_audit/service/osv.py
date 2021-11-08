"""
Functionality for using the [OSV](https://osv.dev/) API as a `VulnerabilityService`.
"""

import json
from typing import List

import requests
from packaging.version import Version

from .interface import Dependency, ServiceError, VulnerabilityResult, VulnerabilityService


class OsvService(VulnerabilityService):
    """
    An implementation of `VulnerabilityService` that uses OSV to provide Python
    package vulnerability information.
    """

    def query(self, spec: Dependency) -> List[VulnerabilityResult]:
        """
        Queries OSV for the given `Dependency` specification.

        See `VulnerabilityService.query`.
        """

        url = "https://api.osv.dev/v1/query"
        query = {
            "package": {"name": spec.canonical_name, "ecosystem": "PyPI"},
            "version": str(spec.version),
        }
        response: requests.Response = requests.post(
            url=url,
            data=json.dumps(query),
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
            return results

        for vuln in response_json["vulns"]:
            id = vuln["id"]
            description = vuln["details"]
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

            results.append(VulnerabilityResult(id, description, fix_versions))

        return results
