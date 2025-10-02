"""
Interfaces for formatting vulnerability results into a string representation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import pip_audit._fix as fix
import pip_audit._service as service


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
        ignored_vulns: dict[service.Dependency, list[service.VulnerabilityResult]] | None = None,
    ) -> str:  # pragma: no cover
        """
        Convert a mapping of dependencies to vulnerabilities into a string.

        `ignored_vulns` is an optional mapping of dependencies to vulnerabilities that were
        ignored via the `--ignore-vuln` CLI flag.
        """
        raise NotImplementedError
