"""
Functionality for using the [OSV](https://osv.dev/) API as a `VulnerabilityService`.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, cast

import requests
from packaging.version import Version

from packaging.specifiers import SpecifierSet

from pip_audit._cache import caching_session
from pip_audit._range_overlap import compute_range_key, specifier_from_osv_range
from pip_audit._range_types import VulnerabilityRangeResult
from pip_audit._service.interface import (
    ConnectionError,
    Dependency,
    ResolvedDependency,
    ServiceError,
    VulnerabilityResult,
    VulnerabilityService,
)

logger = logging.getLogger(__name__)


class OsvService(VulnerabilityService):
    """
    An implementation of `VulnerabilityService` that uses OSV to provide Python
    package vulnerability information.
    """

    DEFAULT_OSV_URL = "https://api.osv.dev/v1/query"

    def __init__(
        self,
        cache_dir: Path | None = None,
        timeout: int | None = None,
        osv_url: str = DEFAULT_OSV_URL,
    ):
        """
        Create a new `OsvService`.

        `cache_dir` is an optional cache directory to use, for caching and reusing OSV API
        requests. If `None`, `pip-audit` will use its own internal caching directory.

        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.
        """
        self.session = caching_session(cache_dir, use_pip=False)
        self.timeout = timeout
        self.osv_url = osv_url

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """
        Queries OSV for the given `Dependency` specification.

        See `VulnerabilityService.query`.
        """
        if spec.is_skipped():
            return spec, []
        spec = cast(ResolvedDependency, spec)

        query = {
            "package": {"name": spec.canonical_name, "ecosystem": "PyPI"},
            "version": str(spec.version),
        }
        try:
            response: requests.Response = self.session.post(
                url=self.osv_url,
                data=json.dumps(query),
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.ConnectTimeout:
            raise ConnectionError("Could not connect to OSV's vulnerability feed")
        except requests.HTTPError as http_error:
            raise ServiceError from http_error

        # If the response is empty, that means that the package/version pair doesn't have any
        # associated vulnerabilities
        #
        # In that case, return an empty list
        results: list[VulnerabilityResult] = []
        response_json = response.json()
        if not response_json:
            return spec, results

        vuln: dict[str, Any]
        for vuln in response_json["vulns"]:
            # Sanity check: only the v1 schema is specified at the moment,
            # and the code below probably won't work with future incompatible
            # schemas without additional changes.
            # The absence of a schema is treated as 1.0.0, per the OSV spec.
            schema_version = Version(vuln.get("schema_version", "1.0.0"))
            if schema_version.major != 1:
                logger.warning(f"Unsupported OSV schema version: {schema_version}")
                continue

            id = vuln["id"]

            # If the vulnerability has been withdrawn, we skip it entirely.
            withdrawn_at = vuln.get("withdrawn")
            if withdrawn_at is not None:
                logger.debug(f"OSV vuln entry '{id}' marked as withdrawn at {withdrawn_at}")
                continue

            # The summary is intended to be shorter, so we prefer it over
            # details, if present. However, neither is required.
            description = vuln.get("summary")
            if description is None:
                description = vuln.get("details")
            if description is None:
                description = "N/A"

            # The "summary" field should be a single line, but "details" might
            # be multiple (Markdown-formatted) lines. So, we normalize our
            # description into a single line (and potentially break the Markdown
            # formatting in the process).
            description = description.replace("\n", " ")

            # OSV doesn't mandate this field either. There's very little we
            # can do without it, so we skip any results that are missing it.
            affecteds = vuln.get("affected")
            if affecteds is None:
                logger.warning(f"OSV vuln entry '{id}' is missing 'affected' list")
                continue

            fix_versions: list[Version] = []
            for affected in affecteds:
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

            results.append(
                VulnerabilityResult.create(
                    ids=[id, *vuln.get("aliases", [])],
                    description=description,
                    fix_versions=fix_versions,
                    published=self._parse_rfc3339(vuln.get("published")),
                )
            )

        return spec, results

    def query_package(self, package_name: str) -> list[VulnerabilityRangeResult]:
        """
        Query OSV for all vulnerabilities affecting any version of a package.

        Unlike query(), this returns range information rather than
        version-specific results. Used for range-based constraint analysis.

        Args:
            package_name: The package name to query (will be canonicalized)

        Returns:
            List of VulnerabilityRangeResult with affected ranges
        """
        from packaging.utils import canonicalize_name

        canonical = canonicalize_name(package_name)

        # Query OSV without a version to get all vulnerabilities for the package
        query = {
            "package": {"name": canonical, "ecosystem": "PyPI"},
        }

        try:
            response: requests.Response = self.session.post(
                url=self.osv_url,
                data=json.dumps(query),
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.ConnectTimeout:
            raise ConnectionError("Could not connect to OSV's vulnerability feed")
        except requests.HTTPError as http_error:
            raise ServiceError from http_error

        results: list[VulnerabilityRangeResult] = []
        response_json = response.json()
        if not response_json:
            return results

        vuln: dict[str, Any]
        for vuln in response_json.get("vulns", []):
            # Sanity check: only the v1 schema is specified at the moment
            schema_version = Version(vuln.get("schema_version", "1.0.0"))
            if schema_version.major != 1:
                logger.warning(f"Unsupported OSV schema version: {schema_version}")
                continue

            vuln_id = vuln["id"]

            # Skip withdrawn vulnerabilities
            withdrawn_at = vuln.get("withdrawn")
            if withdrawn_at is not None:
                logger.debug(f"OSV vuln entry '{vuln_id}' marked as withdrawn at {withdrawn_at}")
                continue

            # Get description
            description = vuln.get("summary") or vuln.get("details") or "N/A"
            description = description.replace("\n", " ")

            # Get affected ranges
            affecteds = vuln.get("affected")
            if affecteds is None:
                logger.warning(f"OSV vuln entry '{vuln_id}' is missing 'affected' list")
                continue

            # Collect affected ranges and fix versions for this package
            # Use a list to preserve union semantics for disjoint ranges
            affected_ranges: list[SpecifierSet] = []
            fix_versions: list[Version] = []
            all_events: list[dict] = []  # Collect events for range_key

            for affected in affecteds:
                pkg = affected.get("package", {})
                # We only care about PyPI
                pkg_name = pkg.get("name", "")
                if canonicalize_name(pkg_name) != canonical:
                    continue
                if pkg.get("ecosystem") != "PyPI":
                    continue

                for range_info in affected.get("ranges", []):
                    if range_info.get("type") != "ECOSYSTEM":
                        continue

                    events = range_info.get("events", [])
                    all_events.extend(events)  # Collect for range_key
                    # Convert events to tuple of SpecifierSets (one per interval)
                    range_specs = specifier_from_osv_range(events)
                    # Extend (not append) - each interval is a separate union member
                    # A version is vulnerable if it matches ANY range
                    affected_ranges.extend(range_specs)

                    # Collect fix versions
                    for event in events:
                        if "fixed" in event:
                            try:
                                fix_versions.append(Version(event["fixed"]))
                            except Exception:
                                pass

            # Sort fix versions
            fix_versions.sort()

            # Compute normalized range_key for grouping
            range_key = compute_range_key(all_events)

            # Get aliases
            aliases = set(vuln.get("aliases", []))

            results.append(
                VulnerabilityRangeResult(
                    id=vuln_id,
                    description=description,
                    affected_ranges=tuple(affected_ranges),
                    fix_versions=fix_versions,
                    aliases=aliases,
                    range_key=range_key,
                    published=self._parse_rfc3339(vuln.get("published")),
                )
            )

        return results
