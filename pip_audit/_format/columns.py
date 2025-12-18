"""
Functionality for formatting vulnerability results as a set of human-readable columns.
"""

from __future__ import annotations

from collections.abc import Iterable
from itertools import zip_longest
from typing import TYPE_CHECKING, Any, cast

from packaging.version import Version

import pip_audit._fix as fix
import pip_audit._service as service

from .interface import VulnerabilityFormat

if TYPE_CHECKING:
    from pip_audit._range_types import (
        ConstraintFinding,
        MetadataCoverage,
        UnsatisfiableEnvelope,
    )


def tabulate(rows: Iterable[Iterable[Any]]) -> tuple[list[str], list[int]]:
    """Return a list of formatted rows and a list of column sizes.
    For example::
    >>> tabulate([['foobar', 2000], [0xdeadbeef]])
    (['foobar     2000', '3735928559'], [10, 4])
    """
    rows = [tuple(map(str, row)) for row in rows]
    sizes = [max(map(len, col)) for col in zip_longest(*rows, fillvalue="")]
    table = [" ".join(map(str.ljust, row, sizes)).rstrip() for row in rows]
    return table, sizes


class ColumnsFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results as a set of
    columns.
    """

    def __init__(self, output_desc: bool, output_aliases: bool):
        """
        Create a new `ColumnFormat`.

        `output_desc` is a flag to determine whether descriptions for each vulnerability should be
        included in the output as they can be quite long and make the output difficult to read.

        `output_aliases` is a flag to determine whether aliases (such as CVEs) for each
        vulnerability should be included in the output.
        """
        self.output_desc = output_desc
        self.output_aliases = output_aliases

    @property
    def is_manifest(self) -> bool:
        """
        See `VulnerabilityFormat.is_manifest`.
        """
        return False

    def format(
        self,
        result: dict[service.Dependency, list[service.VulnerabilityResult]],
        fixes: list[fix.FixVersion],
    ) -> str:
        """
        Returns a column formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        vuln_data: list[list[Any]] = []
        header = ["Name", "Version", "ID", "Fix Versions"]
        if fixes:
            header.append("Applied Fix")
        if self.output_aliases:
            header.append("Aliases")
        if self.output_desc:
            header.append("Description")
        vuln_data.append(header)
        for dep, vulns in result.items():
            if dep.is_skipped():
                continue
            dep = cast(service.ResolvedDependency, dep)
            applied_fix = next((f for f in fixes if f.dep == dep), None)
            for vuln in vulns:
                vuln_data.append(self._format_vuln(dep, vuln, applied_fix))

        columns_string = ""

        # If it's just a header, don't bother adding it to the output
        if len(vuln_data) > 1:
            vuln_strings, sizes = tabulate(vuln_data)

            # Create and add a separator.
            if len(vuln_data) > 0:
                vuln_strings.insert(1, " ".join(map(lambda x: "-" * x, sizes)))

            for row in vuln_strings:
                if columns_string:
                    columns_string += "\n"
                columns_string += row

        # Now display the skipped dependencies
        skip_data: list[list[Any]] = []
        skip_header = ["Name", "Skip Reason"]

        skip_data.append(skip_header)
        for dep, _ in result.items():
            if dep.is_skipped():
                dep = cast(service.SkippedDependency, dep)
                skip_data.append(self._format_skipped_dep(dep))

        # If we only have the header, that means that we haven't skipped any dependencies
        # In that case, don't bother printing the header
        if len(skip_data) <= 1:
            return columns_string

        skip_strings, sizes = tabulate(skip_data)

        # Create separator for skipped dependencies columns
        skip_strings.insert(1, " ".join(map(lambda x: "-" * x, sizes)))

        for row in skip_strings:
            if columns_string:
                columns_string += "\n"
            columns_string += row

        return columns_string

    def _format_vuln(
        self,
        dep: service.ResolvedDependency,
        vuln: service.VulnerabilityResult,
        applied_fix: fix.FixVersion | None,
    ) -> list[Any]:
        vuln_data = [
            dep.canonical_name,
            dep.version,
            vuln.id,
            self._format_fix_versions(vuln.fix_versions),
        ]
        if applied_fix is not None:
            vuln_data.append(self._format_applied_fix(applied_fix))
        if self.output_aliases:
            vuln_data.append(", ".join(vuln.aliases))
        if self.output_desc:
            vuln_data.append(vuln.description)
        return vuln_data

    def _format_fix_versions(self, fix_versions: list[Version]) -> str:
        return ",".join([str(version) for version in fix_versions])

    def _format_skipped_dep(self, dep: service.SkippedDependency) -> list[Any]:
        return [
            dep.canonical_name,
            dep.skip_reason,
        ]

    def _format_applied_fix(self, applied_fix: fix.FixVersion) -> str:
        if applied_fix.is_skipped():
            applied_fix = cast(fix.SkippedFixVersion, applied_fix)
            return (
                f"Failed to fix {applied_fix.dep.canonical_name} ({applied_fix.dep.version}): "
                f"{applied_fix.skip_reason}"
            )
        applied_fix = cast(fix.ResolvedFixVersion, applied_fix)
        return (
            f"Successfully upgraded {applied_fix.dep.canonical_name} ({applied_fix.dep.version} "
            f"=> {applied_fix.version})"
        )

    def format_constraint_findings(
        self,
        findings: list[ConstraintFinding],
        unsatisfiables: list[UnsatisfiableEnvelope],
        coverage: MetadataCoverage,
    ) -> str:
        """
        Format constraint findings as columns.

        Returns a column-formatted string for range mode output.
        Findings are grouped by (package, envelope, range_key) to deduplicate
        advisories with equivalent affected ranges.
        """
        columns_string = ""

        # Group findings by (package_name, envelope_str, range_key)
        if findings:
            grouped: dict[tuple, list["ConstraintFinding"]] = {}
            for finding in findings:
                group_key = (
                    finding.dependency.canonical_name,
                    str(finding.dependency.specifier),
                    finding.vulnerability.range_key,
                )
                if group_key not in grouped:
                    grouped[group_key] = []
                grouped[group_key].append(finding)

            finding_data: list[list[Any]] = []
            header = ["Name", "Envelope", "Vuln IDs", "Affected Range", "Vulnerable Versions"]
            if self.output_desc:
                header.append("Description")
            finding_data.append(header)

            for (pkg_name, envelope_str, _range_key), group in grouped.items():
                first = group[0]

                # Collect all advisory IDs from the group
                all_ids = [f.vulnerability.id for f in group]
                ids_str = ", ".join(all_ids[:3])
                if len(all_ids) > 3:
                    ids_str += f" (+{len(all_ids) - 3})"

                # Truncate vulnerable versions list for display
                vuln_versions = first.vulnerable_versions_permitted[:5]
                versions_str = ", ".join(str(v) for v in vuln_versions)
                if len(first.vulnerable_versions_permitted) > 5:
                    versions_str += f" (+{len(first.vulnerable_versions_permitted) - 5} more)"

                row: list[Any] = [
                    pkg_name,
                    envelope_str or "*",
                    ids_str,
                    first.vulnerability.affected_range_display,
                    versions_str,
                ]
                if self.output_desc:
                    # Truncate description
                    desc = first.vulnerability.description
                    if len(desc) > 60:
                        desc = desc[:57] + "..."
                    row.append(desc)
                finding_data.append(row)

            if len(finding_data) > 1:
                finding_strings, sizes = tabulate(finding_data)
                finding_strings.insert(1, " ".join("-" * s for s in sizes))
                columns_string = "\n".join(finding_strings)

        # Format unsatisfiable envelopes
        if unsatisfiables:
            if columns_string:
                columns_string += "\n\n"

            unsat_data: list[list[Any]] = []
            unsat_header = ["Name", "Conflicting Constraints"]
            unsat_data.append(unsat_header)

            for unsat in unsatisfiables:
                constraints_str = "; ".join(
                    f"{spec} (from {src})" for spec, src in unsat.constraints[:3]
                )
                if len(unsat.constraints) > 3:
                    constraints_str += f" (+{len(unsat.constraints) - 3} more)"
                unsat_data.append([unsat.canonical_name, constraints_str])

            if len(unsat_data) > 1:
                unsat_strings, sizes = tabulate(unsat_data)
                unsat_strings.insert(1, " ".join("-" * s for s in sizes))
                if columns_string:
                    columns_string += "Unsatisfiable Envelopes:\n"
                columns_string += "\n".join(unsat_strings)

        # Add transitive metadata completeness as footer
        if columns_string:
            columns_string += "\n\n"
        columns_string += (
            f"Transitive metadata completeness: "
            f"{coverage.versions_with_requires_dist}/{coverage.versions_examined} versions with metadata "
            f"({coverage.packages_with_requires_dist}/{coverage.packages_total} packages)"
        )

        return columns_string
