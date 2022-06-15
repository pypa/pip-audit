"""
Functionality for formatting vulnerability results as a Markdown table.
"""

import os
from typing import Dict, List, Optional, cast

from packaging.version import Version

import pip_audit._fix as fix
import pip_audit._service as service

from .interface import VulnerabilityFormat


class MarkdownFormat(VulnerabilityFormat):
    def __init__(self, output_desc: bool) -> None:
        """
        Create a new `MarkdownFormat`.

        `output_desc` is a flag to determine whether descriptions for each vulnerability should be
        included in the output as they can be quite long and make the output difficult to read.
        """
        self.output_desc = output_desc

    @property
    def is_manifest(self) -> bool:
        """
        See `VulnerabilityFormat.is_manifest`.
        """
        return False

    def format(
        self,
        result: Dict[service.Dependency, List[service.VulnerabilityResult]],
        fixes: List[fix.FixVersion],
    ) -> str:
        """
        Returns a Markdown formatted string representing a set of vulnerability results and applied
        fixes.
        """
        header = "Name | Version | ID | Fix Versions"
        border = "--- | --- | --- | ---"
        if fixes:
            header += " | Applied Fix"
            border += " | ---"
        if self.output_desc:
            header += " | Description"
            border += " | ---"

        vuln_rows: List[str] = []
        for dep, vulns in result.items():
            if dep.is_skipped():
                continue
            dep = cast(service.ResolvedDependency, dep)
            applied_fix = next((f for f in fixes if f.dep == dep), None)
            for vuln in vulns:
                vuln_rows.append(self._format_vuln(dep, vuln, applied_fix))

        return header + os.linesep + border + os.linesep + os.linesep.join(vuln_rows)

    def _format_vuln(
        self,
        dep: service.ResolvedDependency,
        vuln: service.VulnerabilityResult,
        applied_fix: Optional[fix.FixVersion],
    ) -> str:
        vuln_text = f"{dep.canonical_name} | {dep.version} | {vuln.id} | {self._format_fix_versions(vuln.fix_versions)}"
        if applied_fix is not None:
            vuln_text += self._format_applied_fix(applied_fix)
        if self.output_desc:
            vuln_text += f" | {vuln.description}"
        return vuln_text

    def _format_fix_versions(self, fix_versions: List[Version]) -> str:
        return ",".join([str(version) for version in fix_versions])

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
