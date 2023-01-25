"""
Resolve a list of dependencies via the `resolvelib` API as well as a custom
`Resolver` that uses PyPI as an information source.
"""
from __future__ import annotations

import logging
from pathlib import Path

from packaging.requirements import Requirement
from requests.exceptions import HTTPError
from resolvelib import BaseReporter, Resolver
from resolvelib.resolvers import ResolutionImpossible

from pip_audit._cache import caching_session
from pip_audit._dependency_source import (
    DependencyResolver,
    DependencyResolverError,
    HashMismatchError,
    HashMissingError,
    RequirementHashes,
)
from pip_audit._service.interface import Dependency, ResolvedDependency, SkippedDependency
from pip_audit._state import AuditState

from .pypi_provider import PyPINotFoundError, PyPIProvider

logger = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/simple/"


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
        state: AuditState = AuditState(),
    ) -> None:
        """
        Create a new `ResolveLibResolver`.

        `timeout` and `cache_dir` are optional arguments for HTTP timeouts
        and caching, respectively.

        `state` is an `AuditState` to use for state callbacks.
        """
        self.index_urls = index_urls
        self.timeout = timeout
        # We keep the session here rather than create it within the provider. This is easier to mock
        # since we're creating a new provider on every `resolve` call.
        self.session = caching_session(cache_dir, use_pip=True)
        self.state = state
        self.reporter = BaseReporter()

    def resolve(
        self,
        req: Requirement,
        req_hashes: RequirementHashes,
    ) -> list[Dependency]:
        """
        Resolve the given `Requirement` into a `Dependency` list.
        """

        provider = PyPIProvider(self.index_urls, req_hashes, self.session, self.timeout, self.state)
        resolver: Resolver = Resolver(provider, self.reporter)

        deps: list[Dependency] = []
        try:
            result = resolver.resolve([req])
        except PyPINotFoundError as e:
            skip_reason = str(e)
            logger.debug(skip_reason)
            return [SkippedDependency(name=req.name, skip_reason=skip_reason)]
        except HTTPError as e:
            raise ResolveLibResolverError("failed to resolve dependencies") from e
        except ResolutionImpossible as e:
            raise ResolveLibResolverError(f"impossible resolution: {e}")
        for name, candidate in result.mapping.items():
            # Check hash validity
            if req_hashes:
                try:
                    req_hashes.match(name, candidate.dist_hashes)
                except HashMissingError as e:
                    raise ResolveLibResolverError(
                        "Found dependency without an associated requirements "
                        f"file hash: {str(e)}"
                    ) from e
                except HashMismatchError as e:
                    raise ResolveLibResolverError(str(e)) from e
            deps.append(ResolvedDependency(name, candidate.version))
        return deps


class ResolveLibResolverError(DependencyResolverError):
    """
    A `resolvelib`-specific `DependencyResolverError`.
    """

    pass
