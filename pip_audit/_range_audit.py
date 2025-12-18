"""
Range-based constraint analysis for pip-audit.

This module contains the RangeAuditor class and the _audit_range() entry point
for the --range mode.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Iterator
from pathlib import Path

import tomli
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet

from pip_audit._constraint import ConstraintGraph, build_constraint_graph
from pip_audit._metadata import MetadataProvider, PyPIMetadataProvider
from pip_audit._range_overlap import ranges_overlap
from pip_audit._range_types import (
    ConstrainedDependency,
    ConstraintFinding,
    MetadataCoverage,
    UnsatisfiableEnvelope,
    VulnerabilityRangeResult,
)
from pip_audit._service.osv import OsvService

# Import CLI enums for proper .to_bool() conversion
# These are imported at module level to avoid circular imports at function level
try:
    from pip_audit._cli import (
        OutputFormatChoice,
        VulnerabilityAliasChoice,
        VulnerabilityDescriptionChoice,
    )
except ImportError:
    # Fallback for testing without full CLI
    OutputFormatChoice = None  # type: ignore[misc, assignment]
    VulnerabilityAliasChoice = None  # type: ignore[misc, assignment]
    VulnerabilityDescriptionChoice = None  # type: ignore[misc, assignment]

logger = logging.getLogger(__name__)


class RangeAuditor:
    """
    Auditor for constraint envelope analysis.

    Checks each constraint envelope against vulnerability ranges
    to find cases where declared constraints permit vulnerable versions.
    """

    def __init__(
        self,
        service: OsvService,
        metadata: MetadataProvider,
    ):
        """
        Create a new RangeAuditor.

        Args:
            service: OsvService for querying vulnerabilities
            metadata: MetadataProvider for fetching package info
        """
        self._service = service
        self._metadata = metadata
        self._osv_cache: dict[str, list[VulnerabilityRangeResult]] = {}

    def audit(
        self,
        graph: ConstraintGraph,
    ) -> Iterator[ConstraintFinding]:
        """
        Check each constraint envelope against vulnerability ranges.

        Args:
            graph: The constraint graph with computed envelopes

        Yields:
            ConstraintFinding for each package where constraints permit vulnerable versions
        """
        for name, node in graph.packages.items():
            # Cache OSV results per package
            if name not in self._osv_cache:
                try:
                    self._osv_cache[name] = self._service.query_package(name)
                except Exception as e:
                    logger.warning(f"Failed to query OSV for {name}: {e}")
                    self._osv_cache[name] = []

            vuln_ranges = self._osv_cache[name]
            if not vuln_ranges:
                continue

            # Get package metadata for version list
            pkg_meta = self._metadata.get_metadata(name)
            if not pkg_meta.all_versions:
                logger.debug(f"No versions found for {name}")
                continue

            for vuln in vuln_ranges:
                overlaps, vuln_versions = ranges_overlap(
                    allowed=node.envelope,
                    vulnerable_ranges=vuln.affected_ranges,
                    known_versions=pkg_meta.all_versions,
                    yanked_versions=pkg_meta.yanked_versions,
                )

                if overlaps:
                    yield ConstraintFinding(
                        dependency=ConstrainedDependency(
                            name=name,
                            specifier=node.envelope,
                            constraint_sources=tuple(
                                f"{spec} from {src}" for spec, src in node.constraints
                            ),
                        ),
                        vulnerability=vuln,
                        vulnerable_versions_permitted=vuln_versions,
                    )


def _parse_pyproject(path: Path) -> list[Requirement]:
    """
    Parse direct dependencies from pyproject.toml.

    Args:
        path: Path to pyproject.toml

    Returns:
        List of Requirement objects
    """
    with path.open("rb") as f:
        data = tomli.load(f)

    project = data.get("project")
    if project is None:
        raise ValueError(f"pyproject.toml at {path} has no [project] section")

    deps = project.get("dependencies", [])
    requirements: list[Requirement] = []

    for dep_str in deps:
        try:
            req = Requirement(dep_str)
            requirements.append(req)
        except InvalidRequirement as e:
            logger.warning(f"Skipping invalid requirement '{dep_str}': {e}")

    return requirements


def _format_findings_text(
    findings: list[ConstraintFinding],
    unsatisfiables: list[UnsatisfiableEnvelope],
    coverage: MetadataCoverage,
) -> str:
    """
    Format findings as plain text.

    This is the fallback format when the selected formatter
    doesn't support constraint findings.
    """
    lines: list[str] = []

    # Header
    lines.append("Range Mode Analysis Results")
    lines.append("=" * 40)
    lines.append("")

    # Findings
    if findings:
        lines.append(f"Found {len(findings)} constraint finding(s):")
        lines.append("")

        for finding in findings:
            dep = finding.dependency
            vuln = finding.vulnerability
            lines.append(f"  Package: {dep.name}")
            lines.append(f"  Constraint: {dep.specifier or '*'}")
            lines.append(f"  Vulnerability: {vuln.id}")
            lines.append(f"  Description: {vuln.description[:80]}...")
            lines.append(f"  Affected range: {vuln.affected_range_display}")
            if finding.vulnerable_versions_permitted:
                versions_str = ", ".join(
                    str(v) for v in finding.vulnerable_versions_permitted[:5]
                )
                if len(finding.vulnerable_versions_permitted) > 5:
                    versions_str += f" (+{len(finding.vulnerable_versions_permitted) - 5} more)"
                lines.append(f"  Vulnerable versions permitted: {versions_str}")
            lines.append("")
    else:
        lines.append("No constraint findings.")
        lines.append("")

    # Unsatisfiable envelopes
    if unsatisfiables:
        lines.append(f"Found {len(unsatisfiables)} unsatisfiable envelope(s):")
        lines.append("")
        for unsat in unsatisfiables:
            lines.append(f"  Package: {unsat.name}")
            lines.append("  Conflicting constraints:")
            for spec, source in unsat.constraints:
                lines.append(f"    - {spec} from {source}")
            lines.append("")

    # Transitive metadata completeness
    lines.append("Transitive Metadata Completeness:")
    lines.append(f"  Packages analyzed: {coverage.packages_total}")
    lines.append(f"  Packages with metadata: {coverage.packages_with_requires_dist}")
    lines.append(f"  Versions examined: {coverage.versions_examined}")
    lines.append(f"  Versions with requires_dist: {coverage.versions_with_requires_dist}")
    lines.append(f"  Versions no metadata available: {coverage.versions_no_metadata_available}")
    lines.append(f"  Versions fetch failed: {coverage.versions_fetch_failed}")
    lines.append(f"  Versions parse failed: {coverage.versions_parse_failed}")

    return "\n".join(lines)


def _audit_range(args: argparse.Namespace) -> int:
    """
    Entry point for range mode. Called from _cli.py.

    Returns exit code:
      - 0: Always (unless --range-strict)
      - 1: Only if --range-strict AND findings exist

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code (0 or 1)
    """
    # Determine pyproject.toml path
    project_path = getattr(args, "project_path", None)
    if project_path is None:
        project_path = Path(".")

    pyproject_path = Path(project_path) / "pyproject.toml"
    if not pyproject_path.exists():
        logger.error(f"pyproject.toml not found at {pyproject_path}")
        print(f"Error: pyproject.toml not found at {pyproject_path}", file=sys.stderr)
        return 1

    # Parse direct dependencies
    try:
        direct_deps = _parse_pyproject(pyproject_path)
    except Exception as e:
        logger.error(f"Failed to parse pyproject.toml: {e}")
        print(f"Error: Failed to parse pyproject.toml: {e}", file=sys.stderr)
        return 1

    if not direct_deps:
        print("No dependencies found in pyproject.toml", file=sys.stderr)
        return 0

    # Set up metadata provider
    cache_dir = getattr(args, "cache_dir", None)
    timeout = getattr(args, "timeout", None)
    metadata = PyPIMetadataProvider(cache_dir=cache_dir, timeout=timeout)

    # Build constraint graph (progress messages go to stderr)
    print(f"Analyzing constraints for {len(direct_deps)} direct dependencies...", file=sys.stderr)
    graph, unsatisfiables, coverage = build_constraint_graph(
        direct_deps=direct_deps,
        metadata=metadata,
    )

    print(f"Built constraint graph with {len(graph.packages)} packages", file=sys.stderr)

    # Set up OSV service
    osv_url = getattr(args, "osv_url", None) or OsvService.DEFAULT_OSV_URL
    service = OsvService(cache_dir=cache_dir, timeout=timeout, osv_url=osv_url)

    # Run range audit
    auditor = RangeAuditor(service=service, metadata=metadata)
    findings = list(auditor.audit(graph))

    # Format output
    # Use the formatter if specified and it supports constraint findings
    output_format = getattr(args, "format", None)

    # Convert enum choices to booleans using .to_bool(format_)
    # The CLI provides enum values (On/Off/Auto), not raw booleans
    desc_choice = getattr(args, "desc", None)
    aliases_choice = getattr(args, "aliases", None)

    # Determine effective format for Auto resolution
    effective_format = output_format if output_format is not None else OutputFormatChoice.Columns

    # Convert to bool - handle both enum and raw bool (for testing)
    if desc_choice is not None and hasattr(desc_choice, "to_bool"):
        output_desc = desc_choice.to_bool(effective_format)
    else:
        output_desc = bool(desc_choice) if desc_choice is not None else False

    if aliases_choice is not None and hasattr(aliases_choice, "to_bool"):
        output_aliases = aliases_choice.to_bool(effective_format)
    else:
        output_aliases = bool(aliases_choice) if aliases_choice is not None else False

    if output_format is not None:
        formatter = output_format.to_format(output_desc, output_aliases)
        output = formatter.format_constraint_findings(findings, unsatisfiables, coverage)
        if output:
            print(output)
        else:
            # Formatter returned empty string, use fallback
            output = _format_findings_text(findings, unsatisfiables, coverage)
            print(output)
    else:
        # No formatter specified, use plain text fallback
        output = _format_findings_text(findings, unsatisfiables, coverage)
        print(output)

    # Determine exit code
    range_strict = getattr(args, "range_strict", False)
    if range_strict and (findings or unsatisfiables):
        return 1

    return 0
