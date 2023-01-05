"""
Interfaces for interacting with "dependency sources", i.e. sources
of fully resolved Python dependency trees.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from packaging.requirements import Requirement

from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency


class DependencySource(ABC):
    """
    Represents an abstract source of fully-resolved Python dependencies.

    Individual concrete dependency sources (e.g. `pip list`) are expected
    to subclass `DependencySource` and implement it in their terms.
    """

    @abstractmethod
    def collect(self) -> Iterator[Dependency]:  # pragma: no cover
        """
        Yield the dependencies in this source.
        """
        raise NotImplementedError

    @abstractmethod
    def fix(self, fix_version: ResolvedFixVersion) -> None:  # pragma: no cover
        """
        Upgrade a dependency to the given fix version.
        """
        raise NotImplementedError


class DependencySourceError(Exception):
    """
    Raised when a `DependencySource` fails to provide its dependencies.

    Concrete implementations are expected to subclass this exception to
    provide more context.
    """

    pass


class DependencyFixError(Exception):
    """
    Raised when a `DependencySource` fails to perform a "fix" operation, i.e.
    fails to upgrade a package to a different version.

    Concrete implementations are expected to subclass this exception to provide
    more context.
    """

    pass


class RequirementHashMismatchError(Exception):
    """
    Raised when `RequirementHashes` fails to match a hash for a given
    requirement.
    """

    pass


class RequirementHashes:
    """
    Represents the hashes contained within a requirements file.
    """

    def __init__(self) -> None:
        self.mapping = {}

    def add_req(self, req_name: str, hash_options_mapping: dict[str, list[str]]) -> None:
        self.mapping[req_name] = hash_options_mapping

    def __bool__(self) -> bool:
        return bool(self.mapping)

    def __contains__(self, req_name: str) -> bool:
        return req_name in self.mapping

    def match(self, req_name: str, dist_hashes: dict[str, str]) -> None:
        if req_name not in self.mapping:
            raise RequirementHashMismatchError(f"No hash found for {req_name}")

        for algorithm, hashes in self.mapping[req_name].items():
            for hash_ in hashes:
                if hash_ == dist_hashes[algorithm]:
                    return
        raise RequirementHashMismatchError(
            f"Mismatching hash for {req_name}: none of the supplied hashes "
            f"matched {self.mapping[req_name]}"
        )

    def supported_algorithms(self, req_name: str) -> list[str]:
        return self.mapping[req_name].keys()


class DependencyResolver(ABC):
    """
    Represents an abstract resolver of Python dependencies that takes a single
    dependency and returns all of its transitive dependencies.

    Concrete dependency sources may use a resolver as part of their
    implementation.
    """

    @abstractmethod
    def resolve(
        self, req: Requirement, req_hashes: RequirementHashes
    ) -> list[Dependency]:  # pragma: no cover
        """
        Resolve a single `Requirement` into a list of `Dependency` instances.
        """
        raise NotImplementedError

    def resolve_all(
        self, reqs: Iterator[Requirement], req_hashes: RequirementHashes
    ) -> Iterator[tuple[Requirement, list[Dependency]]]:
        """
        Resolve a collection of `Requirement`s into their respective `Dependency` sets.

        `DependencyResolver` implementations can override this implementation with
        a more optimized one.
        """
        for req in reqs:
            yield (req, self.resolve(req, req_hashes))


class DependencyResolverError(Exception):
    """
    Raised when a `DependencyResolver` fails to resolve its dependencies.

    Concrete implementations are expected to subclass this exception to
    provide more context.
    """

    pass
