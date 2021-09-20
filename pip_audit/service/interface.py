from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator, List, Tuple

from packaging.version import Version


@dataclass(frozen=True)
class Dependency:
    package: str
    version: Version


@dataclass(frozen=True)
class VulnerabilityResult:
    id: str
    description: str
    fix_versions: List[Version]


class VulnerabilityService(ABC):
    @abstractmethod
    def query(self, spec: Dependency) -> List[VulnerabilityResult]:  # pragma: no cover
        raise NotImplementedError

    def query_all(
        self, specs: Iterator[Dependency]
    ) -> Iterator[Tuple[Dependency, List[VulnerabilityResult]]]:
        # Naive implementation that can be overridden if a particular service supports bulk queries
        for spec in specs:
            yield (spec, self.query(spec))


class ServiceError(Exception):
    pass
