"""
Constraint graph building and envelope computation for range-based analysis.

This module implements the monotone fixpoint traversal algorithm for
building a constraint graph from pyproject.toml dependencies.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field

import icontract
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from pip_audit._metadata import MetadataProvider, MetadataStats
from pip_audit._range_types import MetadataCoverage, UnsatisfiableEnvelope

logger = logging.getLogger(__name__)


@dataclass
class PackageNode:
    """A node in the constraint graph representing a package."""

    name: str
    """The canonical package name."""

    constraints: list[tuple[SpecifierSet, str]]
    """
    List of (specifier, source) pairs.
    Each constraint narrows the allowed version range.
    """

    envelope: SpecifierSet = field(default_factory=SpecifierSet)
    """Current computed envelope (intersection of all constraints)."""

    def add_constraint(self, specifier: SpecifierSet, source: str) -> bool:
        """
        Add a constraint and recompute the envelope.

        Returns True if the envelope changed (narrowed) OR this is the first constraint.
        First-time encounters must return True to trigger BFS expansion even for
        unpinned dependencies (empty specifiers).
        """
        is_first = len(self.constraints) == 0
        old_envelope = self.envelope
        self.constraints.append((specifier, source))
        self.envelope = compute_envelope(self.constraints)
        return is_first or str(self.envelope) != str(old_envelope)


@dataclass
class ConstraintGraph:
    """
    The constraint graph for range-based analysis.

    Each node represents a package with accumulated constraints.
    The graph is built by BFS traversal of transitive dependencies.
    """

    packages: dict[str, PackageNode] = field(default_factory=dict)
    """Map from canonical package name to PackageNode."""

    def get_or_create(self, name: str) -> PackageNode:
        """Get or create a node for a package."""
        canonical = canonicalize_name(name)
        if canonical not in self.packages:
            self.packages[canonical] = PackageNode(name=canonical, constraints=[])
        return self.packages[canonical]


def compute_envelope(constraints: list[tuple[SpecifierSet, str]]) -> SpecifierSet:
    """
    Compute Allowed(P) = intersection of all constraints.

    An empty SpecifierSet means "allow all versions".
    The intersection of specifiers narrows the allowed range.

    Args:
        constraints: List of (specifier, source) pairs

    Returns:
        The intersection of all specifiers
    """
    if not constraints:
        return SpecifierSet()  # Empty = all versions allowed

    envelope = SpecifierSet()  # Start with "allow all"
    for spec, _source in constraints:
        if spec:  # Only intersect non-empty specifiers
            if not envelope:
                # First non-empty specifier becomes the envelope
                envelope = spec
            else:
                envelope = envelope & spec

    return envelope


def is_envelope_empty(envelope: SpecifierSet, known_versions: list) -> bool | None:
    """
    Check if an envelope allows any versions.

    Since SpecifierSet doesn't have a direct "is_empty" method,
    we check if any known version satisfies the envelope.

    For practical purposes, if an envelope has conflicting constraints
    like ">2,<1", we detect this by checking against known versions.

    Args:
        envelope: The specifier set to check
        known_versions: List of known versions to test against

    Returns:
        False: At least one version satisfies the envelope
        True: No versions satisfy the envelope (confirmed unsatisfiable)
        None: Unknown (no versions to test against, e.g., metadata unavailable)
    """
    if not envelope:
        return False  # Empty specifier = all allowed

    if not known_versions:
        return None  # Unknown - can't determine satisfiability without versions

    # Check if any version satisfies all constraints
    for v in known_versions:
        if envelope.contains(v):
            return False
    return True


def build_constraint_graph(
    direct_deps: list[Requirement],
    metadata: MetadataProvider,
    max_depth: int = 10,
) -> tuple[ConstraintGraph, list[UnsatisfiableEnvelope], MetadataCoverage]:
    """
    Build a constraint graph using monotone fixpoint traversal.

    Algorithm:
    1. Start with direct deps from pyproject.toml
    2. For each dep, get union of all Requires-Dist from matching versions
    3. Add constraints to transitive deps
    4. Recompute envelope when constraints added
    5. Only re-enqueue neighbors if envelope changed
    6. Track visited to prevent infinite loops
    7. Stop at max_depth or fixpoint

    Args:
        direct_deps: Direct dependencies from pyproject.toml
        metadata: MetadataProvider for fetching package info
        max_depth: Maximum traversal depth

    Returns:
        Tuple of (graph, unsatisfiable_envelopes, metadata_coverage)
    """
    graph = ConstraintGraph()
    unsatisfiable: list[UnsatisfiableEnvelope] = []

    # Track metadata coverage
    packages_seen: set[str] = set()
    packages_with_metadata: set[str] = set()
    stats = MetadataStats()  # Accumulate stats across all get_requires_dist calls

    # Queue: (requirement, source_description, depth)
    queue: deque[tuple[Requirement, str, int]] = deque()

    # Add direct dependencies to queue
    for req in direct_deps:
        queue.append((req, "pyproject.toml", 0))

    while queue:
        req, source, depth = queue.popleft()
        canonical = canonicalize_name(req.name)
        packages_seen.add(canonical)

        # Skip if beyond max depth
        if depth > max_depth:
            logger.debug(f"Skipping {canonical} at depth {depth} (max_depth={max_depth})")
            continue

        # Get or create node
        node = graph.get_or_create(canonical)

        # Add constraint and check if envelope changed
        specifier = req.specifier if req.specifier else SpecifierSet()
        envelope_changed = node.add_constraint(specifier, source)

        # Fetch metadata to check if envelope is satisfiable
        pkg_metadata = metadata.get_metadata(canonical)
        if pkg_metadata.all_versions:
            packages_with_metadata.add(canonical)

        # Check for unsatisfiable envelope
        # Use `is True` to distinguish from None (unknown due to missing metadata)
        if node.constraints and is_envelope_empty(node.envelope, pkg_metadata.all_versions) is True:
            logger.warning(f"Unsatisfiable constraints for {canonical}")
            unsatisfiable.append(
                UnsatisfiableEnvelope(
                    name=canonical,
                    constraints=tuple(node.constraints),
                )
            )
            # Don't traverse further from unsatisfiable packages
            continue

        # Only expand if:
        # 1. The envelope changed (monotone property)
        # 2. We haven't exceeded max_depth
        if envelope_changed and depth < max_depth:
            # Get transitive dependencies from all matching versions
            # Pass stats to accumulate coverage metrics
            trans_deps = metadata.get_requires_dist(canonical, node.envelope, stats)

            for trans_req in trans_deps:
                # Skip deps with markers that evaluate to False
                if trans_req.marker is not None:
                    # Evaluate marker in current environment
                    if not trans_req.marker.evaluate():
                        continue

                # Skip extras in v1 (base deps only)
                if trans_req.extras:
                    logger.debug(f"Skipping extra dependency: {trans_req}")
                    continue

                trans_source = f"{req.name}{req.specifier} from {source}"
                queue.append((trans_req, trans_source, depth + 1))

    # Create coverage from accumulated stats
    coverage = MetadataCoverage(
        packages_total=len(packages_seen),
        packages_with_requires_dist=len(packages_with_metadata),
        versions_examined=stats.versions_examined,
        versions_with_requires_dist=stats.versions_with_requires_dist,
        versions_no_metadata_available=stats.versions_no_metadata_available,
        versions_fetch_failed=stats.versions_fetch_failed,
        versions_parse_failed=stats.versions_parse_failed,
    )

    return graph, unsatisfiable, coverage
