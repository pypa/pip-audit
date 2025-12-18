"""
Interfaces for formatting vulnerability results into a string representation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import pip_audit._fix as fix
import pip_audit._service as service

if TYPE_CHECKING:
    from pip_audit._range_types import (
        ConstraintFinding,
        MetadataCoverage,
        OsvCoverage,
        UnsatisfiableEnvelope,
    )


class VulnerabilityFormat(ABC):
    """
    Represents an abstract string representation for vulnerability results.
    """

    @property
    @abstractmethod
    def is_manifest(self) -> bool:  # pragma: no cover
        """
        Is this format a "manifest" format, i.e. one that prints a summary
        of all results?

        Manifest formats are always rendered emitted unconditionally, even
        if the audit results contain nothing out of the ordinary
        (no vulnerabilities, skips, or fixes).
        """
        raise NotImplementedError

    @abstractmethod
    def format(
        self,
        result: dict[service.Dependency, list[service.VulnerabilityResult]],
        fixes: list[fix.FixVersion],
    ) -> str:  # pragma: no cover
        """
        Convert a mapping of dependencies to vulnerabilities into a string.
        """
        raise NotImplementedError

    def format_constraint_findings(
        self,
        findings: list[ConstraintFinding],
        unsatisfiables: list[UnsatisfiableEnvelope],
        coverage: MetadataCoverage,
        osv_coverage: OsvCoverage | None = None,
    ) -> str:
        """
        Format constraint findings for range mode.

        Default implementation returns empty string. Formatters that want
        to support range mode should override this method.

        If this method returns an empty string, range mode will fall back
        to plain text output.

        Args:
            findings: List of constraint findings (where constraints permit vulnerable versions)
            unsatisfiables: List of packages with unsatisfiable constraint envelopes
            coverage: Metadata coverage statistics
            osv_coverage: OSV query coverage statistics (optional)

        Returns:
            Formatted string, or empty string if not supported
        """
        return ""
