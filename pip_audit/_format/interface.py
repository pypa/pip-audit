"""
Interfaces for formatting vulnerability results into a string representation.
"""
from abc import ABC, abstractmethod
from typing import Dict, List

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
        result: Dict[service.Dependency, List[service.VulnerabilityResult]],
        fixes: List[fix.FixVersion],
    ) -> str:  # pragma: no cover
        """
        Convert a mapping of dependencies to vulnerabilities into a string.
        """
        raise NotImplementedError
