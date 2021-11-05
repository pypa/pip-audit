from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator, List, Tuple

from packaging.utils import canonicalize_name
from packaging.version import Version


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Version

    # TODO(ww): Use functools.cached_property when supported Python is 3.8+.
    @property
    def canonical_name(self) -> str:
        return canonicalize_name(self.name)


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
