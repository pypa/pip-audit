import os
from typing import Iterator

from packaging.requirements import Requirement
from pip_api import parse_requirements
from pip_api._parse_requirements import UnparsedRequirement

from pip_audit.dependency_source import DependencyResolver, DependencySource
from pip_audit.service import Dependency


class RequirementSource(DependencySource):
    def __init__(self, filename: os.PathLike, resolver: DependencyResolver):
        self.filename = filename
        self.resolver = resolver

    def collect(self) -> Iterator[Dependency]:
        reqs = parse_requirements(filename=self.filename)

        # Invoke the dependency resolver to turn requirements into dependencies
        for _, req in reqs.items():
            if isinstance(req, UnparsedRequirement):
                raise RuntimeError
            deps = self.resolver.resolve(Requirement(str(req)))
            for dep in deps:
                yield dep
