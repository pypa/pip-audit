"""
Functionality for formatting vulnerability results using the CycloneDX SBOM format.
"""

import enum
import logging
from typing import Dict, List, cast

from cyclonedx import output
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.vulnerability import Vulnerability
from cyclonedx.parser import BaseParser

import pip_audit._fix as fix
import pip_audit._service as service

from .interface import VulnerabilityFormat

logger = logging.getLogger(__name__)


class _PipAuditResultParser(BaseParser):
    def __init__(self, result: Dict[service.Dependency, List[service.VulnerabilityResult]]):
        super().__init__()

        for (dep, vulns) in result.items():
            # TODO(alex): Is there anything interesting we can do with skipped dependencies in
            # the CycloneDX format?
            if dep.is_skipped():
                continue
            dep = cast(service.ResolvedDependency, dep)

            c = Component(name=dep.name, version=str(dep.version))
            for vuln in vulns:
                c.add_vulnerability(
                    Vulnerability(
                        id=vuln.id,
                        description=vuln.description,
                        recommendation="Upgrade",
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

    @property
    def is_manifest(self) -> bool:
        """
        See `VulnerabilityFormat.is_manifest`.
        """
        return True

    def format(
        self,
        result: Dict[service.Dependency, List[service.VulnerabilityResult]],
        fixes: List[fix.FixVersion],
    ) -> str:
        """
        Returns a CycloneDX formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        if fixes:
            logger.warning("--fix output is unsupported by CycloneDX formats")

        parser = _PipAuditResultParser(result)
        bom = Bom.from_parser(parser)

        formatter = output.get_instance(
            bom=bom,
            output_format=self._inner_format.value,
            schema_version=output.SchemaVersion.V1_4,
        )

        return formatter.output_as_string()
