"""
Functionality for formatting vulnerability results using the CycloneDX SBOM format.
"""

import enum
from typing import Dict, List

from cyclonedx import output
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.vulnerability import Vulnerability
from cyclonedx.parser import BaseParser

import pip_audit.service as service

from .interface import VulnerabilityFormat


class _PipAuditResultParser(BaseParser):
    def __init__(self, result: Dict[service.Dependency, List[service.VulnerabilityResult]]):
        super().__init__()

        for (dep, vulns) in result.items():
            c = Component(name=dep.name, version=str(dep.version))

            # TODO(ww): Figure out if/how we want to include other dependency
            # metadata in the BOM, such as author, license, etc.

            for vuln in vulns:
                # TODO(ww): Figure out if/how we want to include other vulnerability
                # metadata in the BOM, such as source (OSV/PyPI/etc), URL, etc.
                c.add_vulnerability(
                    Vulnerability(
                        id=vuln.id,
                        description=vuln.description,
                        advisories=[f"Upgrade: {v}" for v in vuln.fix_versions],
                        recommendations=["Upgrade"],
                    )
                )

            self._components.append(c)


class CycloneDxFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results using CycloneDX.
    The container format used by CycloneDX can be additionally configured.
    """

    @enum.unique
    class InnerFormat(enum.Enum):
        """
        Valid container formats for CycloneDX.
        """

        Json = output.OutputFormat.JSON
        Xml = output.OutputFormat.XML

    def __init__(self, inner_format: "CycloneDxFormat.InnerFormat"):
        """
        Create a new `CycloneDxFormat`.

        `inner_format` determines the container format used by CycloneDX.
        """

        self._inner_format = inner_format

    def format(self, result: Dict[service.Dependency, List[service.VulnerabilityResult]]) -> str:
        """
        Returns a CycloneDX formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        parser = _PipAuditResultParser(result)
        bom = Bom.from_parser(parser)

        formatter = output.get_instance(bom=bom, output_format=self._inner_format.value)

        return formatter.output_as_string()
