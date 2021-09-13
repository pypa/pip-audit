import json
from typing import Any, Dict, List

import pip_audit.service as service

from .interface import VulnerabilityFormat


class JsonFormat(VulnerabilityFormat):
    def format(self, result: Dict[service.Dependency, List[service.VulnerabilityResult]]) -> str:
        output_json = []
        for dep, vulns in result.items():
            output_json.append(self._format_dep(dep, vulns))
        return json.dumps(output_json)

    def _format_dep(
        self, dep: service.Dependency, vulns: List[service.VulnerabilityResult]
    ) -> Dict[str, Any]:
        return {
            "package": dep.package,
            "version": str(dep.version),
            "vulns": [self._format_vuln(vuln) for vuln in vulns],
        }

    def _format_vuln(self, vuln: service.VulnerabilityResult) -> Dict[str, Any]:
        return {
            "id": vuln.id,
            "description": vuln.description,
            "version_range": [
                self._format_version_range(version) for version in vuln.version_range
            ],
        }

    def _format_version_range(self, version_range: service.VersionRange) -> Dict[str, str]:
        version_range_json = {}
        if version_range.introduced is not None:
            version_range_json["introduced"] = str(version_range.introduced)
        if version_range.fixed is not None:
            version_range_json["fixed"] = str(version_range.fixed)
        return version_range_json
