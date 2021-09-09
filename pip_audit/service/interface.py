from abc import ABC
from dataclasses import dataclass
from typing import Dict, List, Optional

from packaging.version import Version


@dataclass(frozen=True)
class Dependency:
    package: str
    version: Version


@dataclass(frozen=True)
class VulnerabilityResult:
    id: str
    description: str
    version_introduced: Optional[Version]
    version_fixed: Optional[Version]


class VulnerabilityService(ABC):
    def query(self, spec: Dependency) -> List[VulnerabilityResult]:  # pragma: no cover
        raise NotImplementedError

    def query_all(self, specs: List[Dependency]) -> Dict[Dependency, List[VulnerabilityResult]]:
        # Naive implementation that can be overridden if a particular service supports bulk queries
        results: Dict[Dependency, List[VulnerabilityResult]] = {}
        for spec in specs:
            results[spec] = self.query(spec)
        return results
