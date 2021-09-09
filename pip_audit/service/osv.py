import json
from typing import List

import requests

from .interface import Dependency, VulnerabilityResult, VulnerabilityService


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

        # TODO(alex): Figure out what to do here
        assert response.status_code == 200

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
            version_introduced = None
            version_fixed = None
            for ranges in vuln["affects"]["ranges"]:
                # We only care about PyPI versions
                if ranges["type"] == "ECOSYSTEM":
                    if "introduced" in ranges:
                        version_introduced = ranges["introduced"]
                    if "fixed" in ranges:
                        version_fixed = ranges["fixed"]
                    break
            results.append(VulnerabilityResult(id, description, version_introduced, version_fixed))

        return results
