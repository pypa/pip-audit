"""
Metadata provider interface and implementations for range-based analysis.

This module provides an abstract interface for fetching package metadata
(version lists and dependency information) with a swappable implementation.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

import requests
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pip_audit._cache import caching_session

logger = logging.getLogger(__name__)


@dataclass
class VersionMetadata:
    """Metadata for a single version of a package."""

    version: Version
    requires_dist: list[Requirement]
    yanked: bool = False


@dataclass
class MetadataStats:
    """Stats tracking for metadata retrieval (for coverage reporting)."""

    versions_examined: int = 0
    """Versions within envelope for which metadata retrieval was attempted."""

    versions_with_requires_dist: int = 0
    """Versions with successfully parsed requires_dist metadata."""

    versions_no_metadata_available: int = 0
    """Versions with no wheel/sdist metadata available on PyPI."""

    versions_fetch_failed: int = 0
    """Versions where metadata fetch failed (timeout/HTTP error)."""

    versions_parse_failed: int = 0
    """Versions where metadata exists but was unparseable."""


@dataclass
class PackageMetadata:
    """Metadata for a package across all versions."""

    name: str
    """The canonical package name."""

    all_versions: list[Version]
    """All known versions of the package (sorted)."""

    yanked_versions: set[Version]
    """Versions that have been yanked from PyPI."""

    version_metadata: dict[Version, VersionMetadata]
    """Per-version metadata (requires_dist, etc.)."""

    stats: MetadataStats = field(default_factory=MetadataStats)
    """Stats for metadata retrieval failures."""

    @property
    def versions_with_metadata(self) -> list[Version]:
        """Versions that have dependency metadata available."""
        return [v for v in self.all_versions if v in self.version_metadata]


class MetadataProvider(ABC):
    """
    Abstract interface for fetching package metadata.

    Implementations can use different sources:
    - PyPI JSON API (crude but fast)
    - Wheel METADATA files (accurate but slow)
    - Simple index + metadata (future)
    """

    @abstractmethod
    def get_metadata(self, package_name: str) -> PackageMetadata:
        """
        Fetch all versions and their metadata for a package.

        Args:
            package_name: The package name (will be canonicalized)

        Returns:
            PackageMetadata with version list and per-version info
        """
        ...

    @abstractmethod
    def get_requires_dist(
        self,
        package_name: str,
        within_specifier: SpecifierSet,
        stats: MetadataStats | None = None,
    ) -> list[Requirement]:
        """
        Get union of Requires-Dist from ALL versions matching specifier.

        This is used for transitive dependency expansion: we union the
        dependencies of all versions within the constraint to capture
        all possible transitive deps.

        Args:
            package_name: The package name (will be canonicalized)
            within_specifier: Only consider versions matching this specifier
            stats: Optional MetadataStats to accumulate coverage stats

        Returns:
            Union of all Requires-Dist from matching versions
        """
        ...


@dataclass
class PyPIMetadataProvider(MetadataProvider):
    """
    V1 implementation using PyPI JSON API.

    Limitation: PyPI JSON API doesn't reliably give per-version requires_dist.
    The JSON endpoint returns `info.requires_dist` for the latest version,
    and `releases[version]` contains file info but not always dependencies.

    This crude impl may miss some transitive deps. Future providers can
    fetch actual wheel METADATA / sdist PKG-INFO for accuracy.
    """

    cache_dir: Path | None = None
    timeout: int | None = None
    _session: requests.Session = field(init=False, repr=False)
    _package_cache: dict[str, PackageMetadata] = field(
        default_factory=dict, init=False, repr=False
    )

    def __post_init__(self) -> None:
        self._session = caching_session(self.cache_dir, use_pip=False)

    def get_metadata(self, package_name: str) -> PackageMetadata:
        """Fetch all versions and their metadata for a package."""
        canonical = canonicalize_name(package_name)

        # Check cache first
        if canonical in self._package_cache:
            return self._package_cache[canonical]

        url = f"https://pypi.org/pypi/{canonical}/json"
        try:
            response = self._session.get(url, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch metadata for {canonical}: {e}")
            # Return empty metadata on failure
            empty = PackageMetadata(
                name=canonical,
                all_versions=[],
                yanked_versions=set(),
                version_metadata={},
            )
            self._package_cache[canonical] = empty
            return empty

        data = response.json()

        # Parse all versions from releases
        all_versions: list[Version] = []
        yanked_versions: set[Version] = set()
        version_metadata: dict[Version, VersionMetadata] = {}

        for version_str, release_files in data.get("releases", {}).items():
            try:
                version = Version(version_str)
            except InvalidVersion:
                logger.debug(f"Skipping invalid version {version_str} for {canonical}")
                continue

            all_versions.append(version)

            # Check if any file in this release is yanked
            is_yanked = any(f.get("yanked", False) for f in release_files)
            if is_yanked:
                yanked_versions.add(version)

            # Try to get requires_dist from release files
            # PyPI JSON API doesn't reliably include this per-version
            # We'll use the info.requires_dist for the latest version only
            version_metadata[version] = VersionMetadata(
                version=version,
                requires_dist=[],
                yanked=is_yanked,
            )

        # Sort versions
        all_versions.sort()

        # Get requires_dist from info (latest version only)
        # This is a limitation of PyPI JSON API
        latest_requires_dist = self._parse_requires_dist(
            data.get("info", {}).get("requires_dist")
        )
        if latest_requires_dist and all_versions:
            # Assume latest version has the requires_dist from info
            # Find the actual latest (non-yanked) version
            latest_version = data.get("info", {}).get("version")
            if latest_version:
                try:
                    latest_v = Version(latest_version)
                    if latest_v in version_metadata:
                        version_metadata[latest_v] = VersionMetadata(
                            version=latest_v,
                            requires_dist=latest_requires_dist,
                            yanked=latest_v in yanked_versions,
                        )
                except InvalidVersion:
                    pass

        metadata = PackageMetadata(
            name=canonical,
            all_versions=all_versions,
            yanked_versions=yanked_versions,
            version_metadata=version_metadata,
        )
        self._package_cache[canonical] = metadata
        return metadata

    def get_requires_dist(
        self,
        package_name: str,
        within_specifier: SpecifierSet,
        stats: MetadataStats | None = None,
    ) -> list[Requirement]:
        """
        Get union of Requires-Dist from ALL versions matching specifier.

        Due to PyPI JSON API limitations, this typically only returns
        dependencies from the latest version if it matches the specifier.
        """
        metadata = self.get_metadata(package_name)

        # Find all versions matching the specifier (excluding yanked)
        matching_versions = [
            v
            for v in metadata.all_versions
            if v not in metadata.yanked_versions and within_specifier.contains(v)
        ]

        # Track stats if requested
        if stats is not None:
            stats.versions_examined += len(matching_versions)

        # Union all requires_dist from matching versions
        seen_names: set[str] = set()
        result: list[Requirement] = []

        for version in matching_versions:
            vm = metadata.version_metadata.get(version)
            if vm and vm.requires_dist:
                # Has metadata with requires_dist
                if stats is not None:
                    stats.versions_with_requires_dist += 1
                for req in vm.requires_dist:
                    req_name = canonicalize_name(req.name)
                    if req_name not in seen_names:
                        seen_names.add(req_name)
                        result.append(req)
            else:
                # No metadata available for this version
                # (PyPI JSON API limitation - only latest has requires_dist)
                if stats is not None:
                    stats.versions_no_metadata_available += 1

        return result

    def _parse_requires_dist(
        self, requires_dist: list[str] | None
    ) -> list[Requirement]:
        """Parse requires_dist list into Requirement objects."""
        if not requires_dist:
            return []

        result = []
        for req_str in requires_dist:
            try:
                req = Requirement(req_str)
                result.append(req)
            except InvalidRequirement:
                logger.debug(f"Skipping invalid requirement: {req_str}")
                continue

        return result
