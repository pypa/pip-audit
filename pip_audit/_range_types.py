"""
Types for range-based constraint analysis.

These types are parallel to (not inheriting from) the existing Dependency types.
They represent constraint envelopes rather than resolved versions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, NewType

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

if TYPE_CHECKING:
    from pip_audit._range_overlap import RangeKey

# Semantic type aliases to prevent AND/OR confusion in range operations.
#
# AllowedEnvelope: A SpecifierSet representing allowed versions.
#   Semantics: INTERSECTION - version must match ALL specifiers.
#   Example: >=1.0,<2.0 means version must be both >=1.0 AND <2.0.
#
# AffectedUnion: A tuple of SpecifierSets representing vulnerable versions.
#   Semantics: UNION - version is vulnerable if it matches ANY specifier.
#   Example: (<1.5, >=2.0,<2.5) means vulnerable if <1.5 OR (>=2.0 AND <2.5).
#
# While Python's NewType doesn't enforce at runtime, mypy catches mismatches.
AllowedEnvelope = NewType("AllowedEnvelope", SpecifierSet)
AffectedUnion = NewType("AffectedUnion", tuple[SpecifierSet, ...])


@dataclass(frozen=True)
class ConstrainedDependency:
    """
    A package constrained by specifiers (not resolved to a version).

    Unlike ResolvedDependency which has a concrete version, this represents
    the constraint envelope - the set of all versions that satisfy all
    constraints imposed on this package.
    """

    name: str
    """The package's uncanonicalized name."""

    specifier: SpecifierSet
    """The accumulated constraint envelope (intersection of all specifiers)."""

    constraint_sources: tuple[str, ...]
    """
    Sources of constraints on this package.
    E.g., ("pyproject.toml", "requests>=2.0 from urllib3")
    """

    @property
    def canonical_name(self) -> str:
        """The package's PEP-503 canonicalized name."""
        return canonicalize_name(self.name)


@dataclass(frozen=True)
class VulnerabilityRangeResult:
    """
    A vulnerability with its affected version range.

    Unlike VulnerabilityResult which is associated with a specific version,
    this includes the range of versions affected by the vulnerability.
    """

    id: str
    """A service-provided identifier for the vulnerability."""

    description: str
    """A human-readable description of the vulnerability."""

    affected_ranges: tuple[SpecifierSet, ...]
    """
    The ranges of versions affected by this vulnerability (union semantics).
    Multiple SpecifierSets represent disjoint affected intervals, e.g.,
    (<1.0) OR (>=2.0,<2.5). A version is vulnerable if it matches ANY range.
    """

    fix_versions: list[Version]
    """Versions that fix this vulnerability."""

    aliases: set[str]
    """Alternative identifiers for this vulnerability."""

    range_key: "RangeKey" = field(default=())
    """
    Normalized tuple of intervals for grouping.
    Each inner tuple is (lower_bound, upper_bound) with None for unbounded.
    Used for deduplicating advisories with equivalent affected ranges.
    """

    published: datetime | None = None
    """When the vulnerability was first published."""

    @property
    def affected_range_display(self) -> str:
        """Human-readable display of affected ranges (for output)."""
        if not self.affected_ranges:
            return "*"
        if len(self.affected_ranges) == 1:
            return str(self.affected_ranges[0]) or "*"
        # Multiple ranges: show as "(<1.0) OR (>=2.0,<2.5)"
        parts = [f"({s})" if s else "(*)" for s in self.affected_ranges]
        return " OR ".join(parts)


@dataclass(frozen=True)
class ConstraintFinding:
    """
    A finding that declared constraints permit vulnerable versions.

    This represents an overlap between the allowed constraint envelope
    and a vulnerability's affected range.
    """

    dependency: ConstrainedDependency
    """The constrained dependency with the finding."""

    vulnerability: VulnerabilityRangeResult
    """The vulnerability that overlaps with the constraint envelope."""

    vulnerable_versions_permitted: list[Version]
    """
    Specific versions that are both:
    - Permitted by the constraint envelope
    - Affected by the vulnerability
    """


@dataclass(frozen=True)
class UnsatisfiableEnvelope:
    """
    First-class output for when constraints produce an empty envelope.

    This occurs when multiple constraints on a package conflict and
    no version can satisfy all of them.
    """

    name: str
    """The package name with unsatisfiable constraints."""

    constraints: tuple[tuple[SpecifierSet, str], ...]
    """The conflicting constraints: (specifier, source) pairs."""

    @property
    def canonical_name(self) -> str:
        """The package's PEP-503 canonicalized name."""
        return canonicalize_name(self.name)


@dataclass
class MetadataCoverage:
    """
    Track transitive metadata completeness for transparency in output.

    This helps users understand how complete the transitive analysis was.
    The failure buckets partition versions_examined for observability.
    """

    packages_total: int
    """Total number of packages in the constraint graph."""

    packages_with_requires_dist: int
    """Number of packages with available requires_dist metadata."""

    versions_examined: int
    """Versions within envelope for which metadata retrieval was attempted."""

    versions_with_requires_dist: int
    """Versions with successfully parsed requires_dist metadata."""

    versions_no_metadata_available: int
    """Versions with no wheel/sdist metadata available on PyPI."""

    versions_fetch_failed: int
    """Versions where metadata fetch failed (timeout/HTTP error)."""

    versions_parse_failed: int
    """Versions where metadata exists but was unparseable."""

    def to_dict(self) -> dict[str, int]:
        """Convert to a dictionary for JSON serialization."""
        return {
            "packages_total": self.packages_total,
            "packages_with_requires_dist": self.packages_with_requires_dist,
            "versions_examined": self.versions_examined,
            "versions_with_requires_dist": self.versions_with_requires_dist,
            "versions_no_metadata_available": self.versions_no_metadata_available,
            "versions_fetch_failed": self.versions_fetch_failed,
            "versions_parse_failed": self.versions_parse_failed,
        }


@dataclass
class OsvCoverage:
    """
    Track OSV query coverage for transparency in output.

    This helps users understand how complete the vulnerability scan was.
    """

    packages_queried: int
    """Total number of packages for which OSV was queried."""

    packages_with_vulns: int
    """Number of packages with at least one vulnerability found."""

    packages_query_failed: int
    """Number of packages where the OSV query failed (timeout/HTTP error)."""

    def to_dict(self) -> dict[str, int]:
        """Convert to a dictionary for JSON serialization."""
        return {
            "packages_queried": self.packages_queried,
            "packages_with_vulns": self.packages_with_vulns,
            "packages_query_failed": self.packages_query_failed,
        }
