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


class DependencyResolver(ABC):
    """
    Represents an abstract resolver of Python dependencies that takes a single
    dependency and returns all of its transitive dependencies.

    Concrete dependency sources may use a resolver as part of their
    implementation.
    """

    @abstractmethod
    def resolve(self, req: Requirement) -> list[Dependency]:  # pragma: no cover
        """
        Resolve a single `Requirement` into a list of `Dependency` instances.
        """
        raise NotImplementedError

    def resolve_all(
        self, reqs: Iterator[Requirement]
    ) -> Iterator[tuple[Requirement, list[Dependency]]]:
        """
        Resolve a collection of `Requirement`s into their respective `Dependency` sets.

        `DependencyResolver` implementations can override this implementation with
        a more optimized one.
        """
        for req in reqs:
            yield (req, self.resolve(req))


class DependencyResolverError(Exception):
    """
    Raised when a `DependencyResolver` fails to resolve its dependencies.

    Concrete implementations are expected to subclass this exception to
    provide more context.
    """

    pass
