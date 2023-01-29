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


class HashMissingError(Exception):
    """
    Raised when `RequirementHashes` fails to find any hashes for a resolved
    dependency.
    """

    pass


class HashMismatchError(Exception):
    """
    Raised when `RequirementHashes` fails to match a hash for a given
    requirement.
    """

    pass


class UnsupportedHashAlgorithm(Exception):
    """
    Raised when a `DependencyResolver` encounters an unsupported hash algorithm
    in the supplied `RequirementHashes`.
    """

    pass


class RequirementHashes:
    """
    Represents the hashes contained within a requirements file.
    """

    def __init__(self) -> None:
        """
        Create a new `RequirementHashes`.
        """
        self.mapping: dict[str, dict[str, list[str]]] = {}

    def add_req(self, req_name: str, hash_options_mapping: dict[str, list[str]]) -> None:
        """
        Add a set of hashes for a given requirement.

        `req_name`is the name of the requirement to check.

        `hash_options_mapping` is a dictionary mapping from algorithm names to a list of potential
        hashes. Requirements files are allowed to specify multiple hashes of the same algorithm to
        account for different distribution types.
        """
        self.mapping[req_name] = hash_options_mapping

    def __bool__(self) -> bool:
        """
        Check whether any requirements have been added.
        """
        return bool(self.mapping)

    def __contains__(self, req_name: str) -> bool:
        """
        Check whether a given requirement exists in the set of hashes.

        `req_name` is the name of the requirement to check.
        """
        return req_name in self.mapping

    def match(self, req_name: str, dist_hashes: dict[str, str]) -> None:
        """
        Check whether any of the provided hashes match the hashes calculated by the dependency
        resolver.

        `req_name` is the name of the requirement to check.

        `dist_hashes` is a mapping of hash algorithms to calculated hashes.
        """
        if req_name not in self.mapping:
            raise HashMissingError(f"No hashes found for {req_name}")

        for algorithm, hashes in self.mapping[req_name].items():
            for hash_ in hashes:
                if hash_ == dist_hashes[algorithm]:
                    return
        raise HashMismatchError(
            f"Mismatching hash for {req_name}, none of the calculated hashes ({dist_hashes}) "
            f"matched expected ({self.mapping[req_name]})"
        )

    def supported_algorithms(self, req_name: str) -> list[str]:
        """
        Returns a list of hash algorithms that are supported for a given requirement.

        `req_name` is the name of the requirement to check.
        """
        if req_name not in self.mapping:
            return []
        return list(self.mapping[req_name].keys())


class DependencyResolver(ABC):
    """
    Represents an abstract resolver of Python dependencies that takes a list of
    dependencies and returns all of their transitive dependencies.

    Concrete dependency sources may use a resolver as part of their
    implementation.
    """

    @abstractmethod
    def resolve(
        self, reqs: list[Requirement], req_hashes: RequirementHashes
    ) -> list[Dependency]:  # pragma: no cover
        """
        Resolve a list of `Requirement`s into a list of resolved `Dependency`s.
        """
        raise NotImplementedError


class DependencyResolverError(Exception):
    """
    Raised when a `DependencyResolver` fails to resolve its dependencies.

    Concrete implementations are expected to subclass this exception to
    provide more context.
    """

    pass
