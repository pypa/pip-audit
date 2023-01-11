"""
Resolve a list of dependencies via the `resolvelib` API as well as a custom
`Resolver` that uses PyPI as an information source.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Union

from packaging.requirements import Requirement as _Requirement
from pip_api import Requirement as ParsedRequirement
from requests.exceptions import HTTPError
from resolvelib import BaseReporter, Resolver
from resolvelib.resolvers import ResolutionImpossible

from pip_audit._dependency_source import DependencyResolver, DependencyResolverError
from pip_audit._service.interface import Dependency, ResolvedDependency, SkippedDependency
from pip_audit._state import AuditState

from .pypi_provider import PyPINotFoundError, PyPIProvider

logger = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/simple/"


# TODO: Replace with _Requirement | ParsedRequirement once our minimum is 3.10.
Requirement = Union[_Requirement, ParsedRequirement]


class ResolveLibResolver(DependencyResolver):
    """
    An implementation of `DependencyResolver` that uses `resolvelib` as its
    backend dependency resolution strategy.
    """

    def __init__(
        self,
        index_urls: list[str] = [PYPI_URL],
        timeout: int | None = None,
        cache_dir: Path | None = None,
        skip_editable: bool = False,
        state: AuditState = AuditState(),
    ) -> None:
        """
        Create a new `ResolveLibResolver`.

        `timeout` and `cache_dir` are optional arguments for HTTP timeouts
        and caching, respectively.

        `skip_editable` controls whether requirements marked as "editable" are skipped.
        By default, editable requirements are not skipped.

        `state` is an `AuditState` to use for state callbacks.
        """
        self.provider = PyPIProvider(index_urls, timeout, cache_dir, state)
        self.reporter = BaseReporter()
        self.resolver: Resolver = Resolver(self.provider, self.reporter)
        self._skip_editable = skip_editable

    def resolve(self, req: Requirement) -> list[Dependency]:
        """
        Resolve the given `Requirement` into a `Dependency` list.
        """

        # HACK: `resolve` takes both `packaging.Requirement` and `pip_api.Requirement`,
        # since the latter is a subclass. But only the latter knows whether the
        # requirement is editable, so we need to check for it here.
        if isinstance(req, ParsedRequirement):
            if req.editable and self._skip_editable:
                return [
                    SkippedDependency(name=req.name, skip_reason="requirement marked as editable")
                ]

        deps: list[Dependency] = []
        try:
            result = self.resolver.resolve([req])
        except PyPINotFoundError as e:
            skip_reason = str(e)
            logger.debug(skip_reason)
            return [SkippedDependency(name=req.name, skip_reason=skip_reason)]
        except HTTPError as e:
            raise ResolveLibResolverError("failed to resolve dependencies") from e
        except ResolutionImpossible as e:
            raise ResolveLibResolverError(f"impossible resolution: {e}")
        for name, candidate in result.mapping.items():
            deps.append(ResolvedDependency(name, candidate.version))
        return deps


class ResolveLibResolverError(DependencyResolverError):
    """
    A `resolvelib`-specific `DependencyResolverError`.
    """

    pass
