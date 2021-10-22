import logging
from dataclasses import dataclass
from typing import Any, Dict, List

import requests
from packaging.version import InvalidVersion, Version

from .interface import Dependency, ServiceError, VulnerabilityResult, VulnerabilityService

logger = logging.getLogger(__name__)


@dataclass()
class CachedVulnerabilityData:
    etag: str
    response_json: Dict[str, Any]


class PyPIService(VulnerabilityService):
    def __init__(self):
        self.cache: Dict[Dependency, CachedVulnerabilityData] = {}

    def query(self, spec: Dependency) -> List[VulnerabilityResult]:
        cached_data = None
        headers = None
        if spec in self.cache:
            cached_data = self.cache[spec]
            headers = {"If-None-Match": cached_data.etag}

        url = f"https://pypi.org/pypi/{spec.package}/{str(spec.version)}/json"
        response: requests.Response = requests.get(url=url, headers=headers)
        try:
            response.raise_for_status()
        except requests.HTTPError as http_error:
            raise ServiceError from http_error

        if response.status_code == 304:
            if cached_data is None:
                raise ServiceError(
                    f'Received "not modified" response without specifying ETag: {response}'
                )
            logger.debug(f"Using cached entry, cached={cached_data}")
            response_json = cached_data.response_json
        else:
            response_json = response.json()
            new_entry = CachedVulnerabilityData(response.headers["ETag"], response_json)
            if spec in self.cache:
                logger.debug(
                    f"Overwriting existing cache entry, old={self.cache[spec]}, new={new_entry}"
                )
            self.cache[spec] = new_entry

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
