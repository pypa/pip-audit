"""
Collect dependencies from one or more `requirements.txt`-formatted files.
"""

from pathlib import Path
from typing import Iterator, List, Optional, Set

from packaging.requirements import Requirement
from pip_api import parse_requirements
from pip_api.exceptions import PipError

from pip_audit.dependency_source import (
    DependencyResolver,
    DependencyResolverError,
    DependencySource,
    DependencySourceError,
)
from pip_audit.service import Dependency
from pip_audit.state import AuditState


class RequirementSource(DependencySource):
    """
    Wraps `requirements.txt` dependency resolution as a dependency source.
    """

    def __init__(
        self,
        filenames: List[Path],
        resolver: DependencyResolver,
        state: Optional[AuditState] = None,
    ) -> None:
        """
        Create a new `RequirementSource`.

        `filenames` provides the list of filepaths to parse.

        `resolver` is the `DependencyResolver` instance to use.

        `state` is an optional `AuditState` to use for state callbacks.
        """
        self.filenames = filenames
        self.resolver = resolver
        self.state = state

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `RequirementSource`.

        Raises a `RequirementSourceError` on any errors.
        """
        collected: Set[Dependency] = set()
        for filename in self.filenames:
            try:
                reqs = parse_requirements(filename=filename)
            except PipError as pe:
                raise RequirementSourceError("requirement parsing raised an error") from pe

            # Invoke the dependency resolver to turn requirements into dependencies
            req_values: List[Requirement] = [Requirement(str(req)) for req in reqs.values()]
            try:
                for _, deps in self.resolver.resolve_all(iter(req_values)):
                    for dep in deps:
                        # Don't allow duplicate dependencies to be returned
                        if dep in collected:
                            continue
                        if self.state is not None:
                            self.state.update_state(
                                f"Collecting {dep.name} ({dep.version})"
                            )  # pragma: no cover
                        collected.add(dep)
                        yield dep
            except DependencyResolverError as dre:
                raise RequirementSourceError("dependency resolver raised an error") from dre


class RequirementSourceError(DependencySourceError):
    """A requirements-parsing specific `DependencySourceError`."""

    pass
