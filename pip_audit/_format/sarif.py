"""
Functionality for formatting vulnerability results using the SARIF format.
"""

from __future__ import annotations

import json
from typing import cast

import pip_audit._fix as fix
import pip_audit._service as service

from .interface import VulnerabilityFormat, vuln_id_url


class SarifFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results using SARIF.
    """

    def __init__(self, output_desc: bool):
        """
        Create a new `SarifFormat`.

        `output_desc` is a flag to determine whether descriptions for each vulnerability should be
        included in the output as they can be quite long and make the output difficult to read.
        """
        self.output_desc = output_desc

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
        
        sarif_log: dict = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pip-audit",
                            "informationUri": "https://pypi.org/project/pip-audit/",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }

        rules = {}
        results = []

        for dep, vulns in result.items():
            if dep.is_skipped():
                continue
                
            dep = cast(service.ResolvedDependency, dep)
            
            for vuln in vulns:
                if vuln.id not in rules:
                    rule = {
                        "id": vuln.id,
                        "shortDescription": {"text": vuln.description} if self.output_desc else {"text": vuln.id},
                        "helpUri": vuln_id_url(vuln.id),
                    }
                    if self.output_desc:
                        rule["fullDescription"] = {"text": vuln.description}
                    
                    rules[vuln.id] = rule
                
                message_text = f"`{dep.canonical_name}` has a known vulnerability: {vuln.id}"
                if self.output_desc:
                    message_text += f"\n{vuln.description}"

                results.append({
                    "ruleId": vuln.id,
                    "level": "error",
                    "message": {
                        "text": message_text
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "pip-audit"
                                }
                            }
                        }
                    ]
                })

        sarif_log["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
        sarif_log["runs"][0]["results"] = results

        return json.dumps(sarif_log)
