from pathlib import Path
from typing import Iterator, List

from packaging.requirements import Requirement
from pip_api import parse_requirements
from pip_api._parse_requirements import UnparsedRequirement

from pip_audit.dependency_source import (
    DependencyResolver,
    DependencyResolverError,
    DependencySource,
    DependencySourceError,
)
from pip_audit.service import Dependency


class RequirementSource(DependencySource):
    def __init__(self, filenames: List[Path], resolver: DependencyResolver):
        self.filenames = filenames
        self.resolver = resolver

    def collect(self) -> Iterator[Dependency]:
        # TODO(alex): I wonder whether we need to do some deduplication of requirements/dependencies
        # here
        for filename in self.filenames:
            reqs = parse_requirements(filename=filename)

            # Invoke the dependency resolver to turn requirements into dependencies
            for _, req in reqs.items():
                if isinstance(req, UnparsedRequirement):
                    raise RequirementSourceError(
                        f"Requirement source does not support unparsed requirements: {req}"
                    )
                try:
                    deps = self.resolver.resolve(Requirement(str(req)))
                except DependencyResolverError as dre:
                    raise RequirementSourceError("Dependency resolver threw an error") from dre
                for dep in deps:
                    yield dep


class RequirementSourceError(DependencySourceError):
    pass
