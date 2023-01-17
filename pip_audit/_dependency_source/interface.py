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
    Represents an abstract resolver of Python dependencies that takes a list of
    dependencies and returns all of their transitive dependencies.

    Concrete dependency sources may use a resolver as part of their
    implementation.
    """

    @abstractmethod
    def resolve(self, reqs: list[Requirement]) -> list[Dependency]:
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
