"""
Resolve a list of dependencies via the `resolvelib` API as well as a custom
`resolvelib.Provider` that uses PyPI as an information source.
"""

from typing import List

from packaging.requirements import Requirement
from resolvelib import BaseReporter, Resolver

from pip_audit.dependency_source import DependencyResolver
from pip_audit.service.interface import Dependency

from .pypi_wheel_provider import PyPIProvider


class ResolveLibResolver(DependencyResolver):
    def __init__(self):
        self.provider = PyPIProvider()
        self.reporter = BaseReporter()
        self.resolver = Resolver(self.provider, self.reporter)

    def resolve(self, req: Requirement) -> List[Dependency]:
        deps: List[Dependency] = []
        result = self.resolver.resolve([req])
        for name, candidate in result.mapping.items():
            deps.append(Dependency(name, candidate.version))
        return deps
