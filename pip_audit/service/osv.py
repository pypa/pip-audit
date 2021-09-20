import json
from typing import List

import requests
from packaging.version import Version

from .interface import Dependency, ServiceError, VulnerabilityResult, VulnerabilityService


class OsvService(VulnerabilityService):
    def query(self, spec: Dependency) -> List[VulnerabilityResult]:
        # Query OSV's REST API for the given package/version
        url = "https://api.osv.dev/v1/query"
        query = {
            "package": {"name": spec.package, "ecosystem": "PyPI"},
            "version": str(spec.version),
        }
        response: requests.Response = requests.post(
            url=url,
            data=json.dumps(query),
        )

        results: List[VulnerabilityResult] = []

        # Check for an unsuccessful status code
        if response.status_code != 200:
            raise ServiceError(f"Received an unsuccessful status code: {response.status_code}")

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
                if pkg["name"] == spec.package and pkg["ecosystem"] == "PyPI":
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
            results.append(VulnerabilityResult(id, description, fix_versions))

        return results
