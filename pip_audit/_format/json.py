"""
Functionality for formatting vulnerability results as an array of JSON objects.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pip_audit._fix as fix
import pip_audit._service as service

from .interface import VulnerabilityFormat

if TYPE_CHECKING:
    from pip_audit._range_types import (
        ConstraintFinding,
        MetadataCoverage,
        UnsatisfiableEnvelope,
    )


class JsonFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results as an array of
    JSON objects.
    """

    def __init__(self, output_desc: bool, output_aliases: bool):
        """
        Create a new `JsonFormat`.

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
        return True

    def format(
        self,
        result: dict[service.Dependency, list[service.VulnerabilityResult]],
        fixes: list[fix.FixVersion],
    ) -> str:
        """
        Returns a JSON formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        output_json = {}
        dep_json = []
        for dep, vulns in result.items():
            dep_json.append(self._format_dep(dep, vulns))
        output_json["dependencies"] = dep_json
        fix_json = []
        for f in fixes:
            fix_json.append(self._format_fix(f))
        output_json["fixes"] = fix_json
        return json.dumps(output_json)

    def _format_dep(
        self, dep: service.Dependency, vulns: list[service.VulnerabilityResult]
    ) -> dict[str, Any]:
        if dep.is_skipped():
            dep = cast(service.SkippedDependency, dep)
            return {
                "name": dep.canonical_name,
                "skip_reason": dep.skip_reason,
            }

        dep = cast(service.ResolvedDependency, dep)
        return {
            "name": dep.canonical_name,
            "version": str(dep.version),
            "vulns": [self._format_vuln(vuln) for vuln in vulns],
        }

    def _format_vuln(self, vuln: service.VulnerabilityResult) -> dict[str, Any]:
        vuln_json = {
            "id": vuln.id,
            "fix_versions": [str(version) for version in vuln.fix_versions],
        }
        if self.output_aliases:
            vuln_json["aliases"] = list(vuln.aliases)
        if self.output_desc:
            vuln_json["description"] = vuln.description
        return vuln_json

    def _format_fix(self, fix_version: fix.FixVersion) -> dict[str, Any]:
        if fix_version.is_skipped():
            fix_version = cast(fix.SkippedFixVersion, fix_version)
            return {
                "name": fix_version.dep.canonical_name,
                "version": str(fix_version.dep.version),
                "skip_reason": fix_version.skip_reason,
            }
        fix_version = cast(fix.ResolvedFixVersion, fix_version)
        return {
            "name": fix_version.dep.canonical_name,
            "old_version": str(fix_version.dep.version),
            "new_version": str(fix_version.version),
        }

    def format_constraint_findings(
        self,
        findings: list[ConstraintFinding],
        unsatisfiables: list[UnsatisfiableEnvelope],
        coverage: MetadataCoverage,
    ) -> str:
        """
        Format constraint findings as JSON.

        Returns a JSON object with constraint_findings, unsatisfiable_envelopes,
        and transitive_metadata_completeness keys.

        Findings are grouped by (package, envelope, range_key) to deduplicate
        advisories with equivalent affected ranges.
        """
        output: dict[str, Any] = {}

        # Group findings by (package_name, envelope_str, range_key)
        # This deduplicates advisories like GHSA + PYSEC for the same issue
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

        # Format grouped findings
        findings_json = []
        for (pkg_name, envelope_str, _range_key), group in grouped.items():
            # Collect all advisory IDs and aliases from the group
            all_ids = [f.vulnerability.id for f in group]
            all_aliases: set[str] = set()
            for f in group:
                all_aliases.update(f.vulnerability.aliases)

            # Use first finding for common fields (they're the same within group)
            first = group[0]

            # Sort constraint sources: "pyproject.toml" first, then alpha
            sources = list(first.dependency.constraint_sources)
            sources.sort(key=lambda s: (0 if s == "pyproject.toml" else 1, s))

            finding_json: dict[str, Any] = {
                "name": pkg_name,
                "envelope": envelope_str or "*",
                "constraint_sources": sources,
                "vulnerability": {
                    "ids": all_ids,
                    "affected_range": first.vulnerability.affected_range_display,
                    "fix_versions": [str(v) for v in first.vulnerability.fix_versions],
                },
                "vulnerable_versions_permitted": [
                    str(v) for v in first.vulnerable_versions_permitted
                ],
            }
            if self.output_aliases:
                finding_json["vulnerability"]["aliases"] = sorted(all_aliases)
            if self.output_desc:
                finding_json["vulnerability"]["description"] = first.vulnerability.description
            findings_json.append(finding_json)
        output["constraint_findings"] = findings_json

        # Format unsatisfiable envelopes
        unsatisfiables_json = []
        for unsat in unsatisfiables:
            unsat_json = {
                "name": unsat.canonical_name,
                "constraints": [
                    {"specifier": str(spec), "source": source}
                    for spec, source in unsat.constraints
                ],
            }
            unsatisfiables_json.append(unsat_json)
        output["unsatisfiable_envelopes"] = unsatisfiables_json

        # Format transitive metadata completeness
        output["transitive_metadata_completeness"] = coverage.to_dict()

        return json.dumps(output)
