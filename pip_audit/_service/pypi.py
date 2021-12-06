"""
Functionality for using the [PyPI](https://warehouse.pypa.io/api-reference/json.html)
API as a `VulnerabilityService`.
"""

import logging
from pathlib import Path
from typing import List, Optional, Tuple, cast

import requests
from packaging.version import InvalidVersion, Version

from pip_audit._cache import caching_session
from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    ServiceError,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)

logger = logging.getLogger(__name__)


class PyPIService(VulnerabilityService):
    """
    An implementation of `VulnerabilityService` that uses PyPI to provide Python
    package vulnerability information.
    """

    def __init__(self, cache_dir: Optional[Path] = None, timeout: Optional[int] = None) -> None:
        """
        Create a new `PyPIService`.

        `cache_dir` is an optional cache directory to use, for caching and reusing PyPI API
        requests. If `None`, `pip-audit` will attempt to use `pip`'s cache directory before falling
        back on its own default cache directory.

        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.
        """
        self.session = caching_session(cache_dir)
        self.timeout = timeout

    def query(self, spec: Dependency) -> Tuple[Dependency, List[VulnerabilityResult]]:
        """
        Queries PyPI for the given `Dependency` specification.

        See `VulnerabilityService.query`.
        """
        if spec.is_skipped():
            return spec, []
        spec = cast(ResolvedDependency, spec)

        url = f"https://pypi.org/pypi/{spec.canonical_name}/{str(spec.version)}/json"
        response: requests.Response = self.session.get(url=url, timeout=self.timeout)
        try:
            response.raise_for_status()
        except requests.HTTPError as http_error:
            if response.status_code == 404:
                skip_reason = (
                    "Dependency not found on PyPI and could not be audited: "
                    f"{spec.canonical_name} ({spec.version})"
                )
                logger.debug(skip_reason)
                return SkippedDependency(name=spec.name, skip_reason=skip_reason), []
            raise ServiceError from http_error

        response_json = response.json()
        results: List[VulnerabilityResult] = []

        vulns = response_json.get("vulnerabilities")

        # No `vulnerabilities` key means that there are no vulnerabilities for any version
        if vulns is None:
            return spec, results

        for v in vulns:
            # Put together the fix versions list
            try:
                fix_versions = [Version(fixed_in) for fixed_in in v["fixed_in"]]
            except InvalidVersion as iv:
                raise ServiceError(f'Received malformed version from PyPI: {v["fixed_in"]}') from iv

            # The ranges aren't guaranteed to come in chronological order
            fix_versions.sort()

            results.append(VulnerabilityResult(v["id"], v["details"], fix_versions))

        return spec, results
