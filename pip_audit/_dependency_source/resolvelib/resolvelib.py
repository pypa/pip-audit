"""
Resolve a list of dependencies via the `resolvelib` API as well as a custom
`Resolver` that uses PyPI as an information source.
"""

import logging
from pathlib import Path
from typing import List, Optional

from packaging.requirements import Requirement
from requests.exceptions import HTTPError
from resolvelib import BaseReporter, Resolver

from pip_audit._dependency_source import DependencyResolver, DependencyResolverError
from pip_audit._service.interface import Dependency, ResolvedDependency, SkippedDependency
from pip_audit._state import AuditState

from .pypi_provider import PyPINotFoundError, PyPIProvider

logger = logging.getLogger(__name__)


class ResolveLibResolver(DependencyResolver):
    """
    An implementation of `DependencyResolver` that uses `resolvelib` as its
    backend dependency resolution strategy.
    """

    def __init__(
        self,
        timeout: Optional[int] = None,
        cache_dir: Optional[Path] = None,
        state: AuditState = AuditState(),
    ) -> None:
        """
        Create a new `ResolveLibResolver`.

        `timeout` and `cache_dir` are optional arguments for HTTP timeouts
        and caching, respectively.

        `state` is an `AuditState` to use for state callbacks.
        """
        self.provider = PyPIProvider(timeout, cache_dir, state)
        self.reporter = BaseReporter()
        self.resolver: Resolver = Resolver(self.provider, self.reporter)

    def resolve(self, req: Requirement) -> List[Dependency]:
        """
        Resolve the given `Requirement` into a `Dependency` list.
        """
        deps: List[Dependency] = []
        try:
            result = self.resolver.resolve([req])
        except PyPINotFoundError as e:
            skip_reason = str(e)
            logger.debug(skip_reason)
            return [SkippedDependency(name=req.name, skip_reason=skip_reason)]
        except HTTPError as e:
            raise ResolveLibResolverError("failed to resolve dependencies") from e
        for name, candidate in result.mapping.items():
            deps.append(ResolvedDependency(name, candidate.version))
        return deps


class ResolveLibResolverError(DependencyResolverError):
    """
    A `resolvelib`-specific `DependencyResolverError`.
    """

    pass
