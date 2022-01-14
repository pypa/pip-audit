"""
Interfaces for formatting vulnerability results into a string representation.
"""
from abc import ABC
from typing import Dict, List

import pip_audit._fix as fix
import pip_audit._service as service


class VulnerabilityFormat(ABC):
    """
    Represents an abstract string representation for vulnerability results.
    """

    def format(
        self,
        result: Dict[service.Dependency, List[service.VulnerabilityResult]],
        fixes: List[fix.FixVersion],
    ) -> str:  # pragma: no cover
        """
        Convert a mapping of dependencies to vulnerabilities into a string.
        """
        raise NotImplementedError
