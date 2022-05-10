"""
Interfaces for interacting with vulnerability services, i.e. sources
of vulnerability information for fully resolved Python packages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Set, Tuple

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

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
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
    hashes: Dict[str, List[str]] = field(default_factory=dict, hash=False)


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

    aliases: Set[str]
    """
    A set of aliases (alternative identifiers) for this result.
    """

    def alias_of(self, other: VulnerabilityResult) -> bool:
        """
        Returns whether this result is an "alias" of another result.

        Two results are said to be aliases if their respective sets of
        `{id, *aliases}` intersect at all. A result is therefore its own alias.
        """
        return bool((self.aliases | {self.id}).intersection(other.aliases | {other.id}))

    def merge_aliases(self, other: VulnerabilityResult) -> VulnerabilityResult:
        """
        Merge `other`'s aliases into this result, returning a new result.
        """

        # Our own ID should never occur in the alias set.
        return VulnerabilityResult(
            self.id, self.description, self.fix_versions, self.aliases | other.aliases - {self.id}
        )

    def has_any_id(self, ids: Set[str]) -> bool:
        """
        Returns whether ids intersects with {id} | aliases.
        """
        return bool(ids & (self.aliases | {self.id}))


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
