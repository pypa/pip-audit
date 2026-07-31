"""
Functionality for formatting vulnerability results as SARIF.
"""

from __future__ import annotations

import json
import logging
from typing import Any, cast

import pip_audit._fix as fix
import pip_audit._service as service
from pip_audit import __version__

from .interface import VulnerabilityFormat, vuln_id_url

logger = logging.getLogger(__name__)

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_TOOL_INFORMATION_URI = "https://github.com/pypa/pip-audit"


class SarifFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results as SARIF 2.1.0.

    Source locations (`physicalLocation`) are intentionally omitted: dependency audits often have
    no stable file/line/column. Schema-valid SARIF without locations is still useful for tooling
    that consumes the report as an artifact.
    """

    def __init__(self, output_desc: bool, output_aliases: bool):
        """
        Create a new `SarifFormat`.

        `output_desc` controls whether vulnerability descriptions are included in rule metadata
        and result messages.

        `output_aliases` controls whether alias IDs (such as CVEs) are included in rule properties.
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
        Returns a SARIF formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        if fixes:
            logger.warning("--fix output is unsupported by the SARIF format")

        rules_by_id: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for dep, vulns in result.items():
            if dep.is_skipped():
                continue

            dep = cast(service.ResolvedDependency, dep)
            for vuln in vulns:
                if vuln.id not in rules_by_id:
                    rules_by_id[vuln.id] = self._format_rule(vuln)
                results.append(self._format_result(dep, vuln))

        output: dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pip-audit",
                            "version": __version__,
                            "informationUri": _TOOL_INFORMATION_URI,
                            "rules": list(rules_by_id.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(output)

    def _format_rule(self, vuln: service.VulnerabilityResult) -> dict[str, Any]:
        short_text = vuln.id
        if self.output_desc and vuln.description:
            short_text = vuln.description.splitlines()[0][:256]

        rule: dict[str, Any] = {
            "id": vuln.id,
            "shortDescription": {"text": short_text},
            "helpUri": vuln_id_url(vuln.id),
        }
        if self.output_desc and vuln.description:
            rule["fullDescription"] = {"text": vuln.description}

        properties: dict[str, Any] = {}
        if vuln.fix_versions:
            properties["fix_versions"] = [str(version) for version in vuln.fix_versions]
        if self.output_aliases and vuln.aliases:
            properties["aliases"] = sorted(vuln.aliases)
        if properties:
            rule["properties"] = properties

        return rule

    def _format_result(
        self, dep: service.ResolvedDependency, vuln: service.VulnerabilityResult
    ) -> dict[str, Any]:
        message = f"{dep.canonical_name}@{dep.version} is vulnerable to {vuln.id}"
        if self.output_desc and vuln.description:
            message = f"{message}: {vuln.description}"

        result: dict[str, Any] = {
            "ruleId": vuln.id,
            "level": "error",
            "message": {"text": message},
            "properties": {
                "package": dep.canonical_name,
                "version": str(dep.version),
            },
        }
        return result
