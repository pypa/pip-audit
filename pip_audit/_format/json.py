"""
Functionality for formatting vulnerability results as an array of JSON objects.
"""

import json
from typing import Any, Dict, List, cast

import pip_audit._service as service

from .interface import VulnerabilityFormat


class JsonFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results as an array of
    JSON objects.
    """

    def __init__(self, output_desc: bool):
        """
        Create a new `JsonFormat`.

        `output_desc` is a flag to determine whether descriptions for each vulnerability should be
        included in the output as they can be quite long and make the output difficult to read.
        """
        self.output_desc = output_desc

    def format(self, result: Dict[service.Dependency, List[service.VulnerabilityResult]]) -> str:
        """
        Returns a JSON formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        output_json = []
        for dep, vulns in result.items():
            output_json.append(self._format_dep(dep, vulns))
        return json.dumps(output_json)

    def _format_dep(
        self, dep: service.Dependency, vulns: List[service.VulnerabilityResult]
    ) -> Dict[str, Any]:
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

    def _format_vuln(self, vuln: service.VulnerabilityResult) -> Dict[str, Any]:
        vuln_json = {
            "id": vuln.id,
            "fix_versions": [str(version) for version in vuln.fix_versions],
        }
        if self.output_desc:
            vuln_json["description"] = vuln.description
        return vuln_json
