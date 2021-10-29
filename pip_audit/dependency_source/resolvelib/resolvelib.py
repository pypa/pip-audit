"""
Resolve a list of dependencies via the `resolvelib` API as well as a custom
`resolvelib.Provider` that uses PyPI as an information source.
"""

from typing import List, Optional

from packaging.requirements import Requirement
from requests.exceptions import HTTPError
from resolvelib import BaseReporter, Resolver

from pip_audit.dependency_source import DependencyResolver, DependencyResolverError
from pip_audit.service.interface import Dependency
from pip_audit.state import AuditState

from .pypi_provider import PyPIProvider


class ResolveLibResolver(DependencyResolver):
    def __init__(self, state: Optional[AuditState] = None):
        self.provider = PyPIProvider(state)
        self.reporter = BaseReporter()
        self.resolver: Resolver = Resolver(self.provider, self.reporter)

    def resolve(self, req: Requirement) -> List[Dependency]:
        deps: List[Dependency] = []
        try:
            result = self.resolver.resolve([req])
        except HTTPError as e:
            raise ResolveLibResolverError("failed to resolve dependencies") from e
        for name, candidate in result.mapping.items():
            deps.append(Dependency(name, candidate.version))
        return deps


class ResolveLibResolverError(DependencyResolverError):
    pass
