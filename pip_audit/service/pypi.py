from typing import List

import requests
from packaging.version import InvalidVersion, Version

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

        vulns = response_json.get("vulnerabilities")

        # No `vulnerabilities` key means that there are no vulnerabilities for any version
        if vulns is None:
            return results

        for v in vulns:
            # Put together the fix versions list
            try:
                fix_versions = [Version(fixed_in) for fixed_in in v["fixed_in"]]
            except InvalidVersion as iv:
                raise ServiceError(f'Received malformed version from PyPI: {v["fixed_in"]}') from iv

            # The ranges aren't guaranteed to come in chronological order
            fix_versions.sort()

            results.append(VulnerabilityResult(v["id"], v["details"], fix_versions))

        return results
