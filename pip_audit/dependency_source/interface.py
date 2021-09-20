from abc import ABC, abstractmethod
from typing import Iterator, List, Tuple

from packaging.requirements import Requirement

from pip_audit.service import Dependency


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


class DependencySourceError(Exception):
    """
    Raised when a `DependencySource` fails to provide its dependencies.

    Concrete implementations are expected to subclass this exception to
    provide more context.
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
    def resolve(self, req: Requirement) -> List[Dependency]:  # pragma: no cover
        raise NotImplementedError

    def resolve_all(
        self, reqs: Iterator[Requirement]
    ) -> Iterator[Tuple[Requirement, List[Dependency]]]:
        # Naive implementation that can be overriden if a particular resolver is
        # designed to resolve a list of dependencies
        for req in reqs:
            yield (req, self.resolve(req))
