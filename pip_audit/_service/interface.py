"""
Interfaces for interacting with vulnerability services, i.e. sources
of vulnerability information for fully resolved Python packages.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator, List, Tuple

from packaging.utils import canonicalize_name
from packaging.version import Version


@dataclass(frozen=True)
class Dependency:
    """
    Represents an abstract Python package.

    This class cannot be constructed directly.
    """

    name: str
    """
    The package's **uncanonicalized** name.

    Use the `canonicalized_name` property when a canonicalized form is necessary.
    """

    def __init__(self, *_args, **_kwargs) -> None:
        """
        A stub constructor that always fails.
        """
        raise NotImplementedError

    # TODO(ww): Use functools.cached_property when supported Python is 3.8+.
    @property
    def canonical_name(self) -> str:
        """
        The `Dependency`'s PEP-503 canonicalized name.
        """
        return canonicalize_name(self.name)

    def is_skipped(self) -> bool:
        """
        Check whether the `Dependency` was skipped by the audit.
        """
        return self.__class__ is SkippedDependency


@dataclass(frozen=True)
class ResolvedDependency(Dependency):
    """
    Represents a fully resolved Python package.
    """

    version: Version


@dataclass(frozen=True)
class SkippedDependency(Dependency):
    """
    Represents a Python package that was unable to be audited and therefore, skipped.
    """

    skip_reason: str


@dataclass(frozen=True)
class VulnerabilityResult:
    """
    Represents a "result" from a vulnerability service, indicating a vulnerability
    in some Python package.
    """

    id: str
    """
    A service-provided identifier for the vulnerability.
    """

    description: str
    """
    A human-readable description of the vulnerability.
    """

    fix_versions: List[Version]
    """
    A list of versions that can be upgraded to that resolve the vulnerability.
    """


class VulnerabilityService(ABC):
    """
    Represents an abstract provider of Python package vulnerability information.
    """

    @abstractmethod
    def query(
        self, spec: Dependency
    ) -> Tuple[Dependency, List[VulnerabilityResult]]:  # pragma: no cover
        """
        Query the `VulnerabilityService` for information about the given `Dependency`,
        returning a list of `VulnerabilityResult`.
        """
        raise NotImplementedError

    def query_all(
        self, specs: Iterator[Dependency]
    ) -> Iterator[Tuple[Dependency, List[VulnerabilityResult]]]:
        """
        Query the vulnerability service for information on multiple dependencies.

        `VulnerabilityService` implementations can override this implementation with
        a more optimized one, if they support batched or bulk requests.
        """
        for spec in specs:
            yield self.query(spec)


class ServiceError(Exception):
    """
    Raised when a `VulnerabilityService` fails, for any reason.

    Concrete implementations of `VulnerabilityService` are expected to subclass
    this exception to provide more context.
    """

    pass
