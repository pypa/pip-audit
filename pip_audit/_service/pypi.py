"""
Functionality for using the [PyPI](https://warehouse.pypa.io/api-reference/json.html)
API as a `VulnerabilityService`.
"""

import logging
from pathlib import Path
from typing import List, Optional, Tuple, cast

import requests
from packaging.utils import canonicalize_version
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

        # If the dependency has a hash explicitly listed, check it against the PyPI data
        if spec.hashes:
            # NOTE: PyPI has lots of "legacy" version formats in old releases.
            # To handle these, we attempt to parse and canonicalize them as
            # PEP 440 versions, falling back on the unparsed version.
            releases = {}
            for r, v in response_json["releases"].items():
                try:
                    releases[canonicalize_version(Version(r))] = v
                except InvalidVersion:
                    releases[r] = v
            release = releases.get(canonicalize_version(spec.version))
            if release is None:
                raise ServiceError(
                    "Could not find release to compare hashes: "
                    f"{spec.canonical_name} ({spec.version})"
                )
            for hash_type, hash_values in spec.hashes.items():
                for hash_value in hash_values:
                    found = False
                    for dist in release:
                        digests = dist["digests"]
                        pypi_hash = digests.get(hash_type)
                        if pypi_hash is not None and pypi_hash == hash_value:
                            found = True
                            break
                    if not found:
                        raise ServiceError(
                            f"Mismatched hash for {spec.canonical_name} ({spec.version}): listed "
                            f"{hash_value} of type {hash_type} could not be found in PyPI releases"
                        )

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

            results.append(
                VulnerabilityResult(v["id"], v["details"], fix_versions, set(v["aliases"]))
            )

        return spec, results
