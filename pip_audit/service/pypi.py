from typing import List

import requests
from packaging.version import Version

from .interface import Dependency, ServiceError, VulnerabilityResult, VulnerabilityService


class PyPIService(VulnerabilityService):
    def query(self, spec: Dependency) -> List[VulnerabilityResult]:
        url = f"https://pypi.org/pypi/{spec.package}/{str(spec.version)}/json"
        response: requests.Response = requests.get(url=url)
        try:
            response.raise_for_status()
        except requests.HTTPError as http_error:
            raise ServiceError from http_error

        response_json = response.json()
        results: List[VulnerabilityResult] = []

        # No `vulns` key means that there are no vulnerabilities for any version
        if "vulns" not in response_json:
            return results

        vulns = response_json["vulns"]

        # If the current version doesn't exist in the `vulns` array
        if str(spec.version) not in vulns:
            return results

        version_vulns = vulns[str(spec.version)]
        for v in version_vulns:
            # Put together the fix versions list
            fix_versions: List[Version] = []
            ranges = v["ranges"]
            for r in ranges:
                if "fixed" in r:
                    fix_versions.append(Version(r["fixed"]))

            # The ranges aren't guaranteed to come in chronological order
            fix_versions.sort()

            results.append(VulnerabilityResult(v["id"], v["details"], fix_versions))

        return results
