"""
Resolve a list of dependencies via the `resolvelib` API as well as a custom
`Resolver` that uses PyPI as an information source.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import cast

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
from pip_audit._dependency_source.requirement import RequirementDependency
from pip_audit._service.interface import Dependency, SkippedDependency
from pip_audit._state import AuditState

from .pypi_provider import Candidate, PyPIProvider, ResolvedCandidate, SkippedCandidate

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

    def resolve(self, reqs: list[Requirement], req_hashes: RequirementHashes) -> list[Dependency]:
        """
        Resolve the given `Requirement` into a `Dependency` list.
        """

        deps: list[Dependency] = []

        provider = PyPIProvider(self.index_urls, req_hashes, self.session, self.timeout, self.state)
        resolver: Resolver = Resolver(provider, self.reporter)

        try:
            result = resolver.resolve(reqs)
        except HTTPError as e:
            raise ResolveLibResolverError("failed to resolve dependencies") from e
        except ResolutionImpossible as e:
            raise ResolveLibResolverError(f"impossible resolution: {e}")

        # If the provider encountered any dependencies it couldn't find on PyPI, they'll be here.
        deps.extend(provider.skip_deps)

        # Construct dependee mapping to figure out what top-level requirements correspond to what
        # dependencies.
        dependee_map = _build_dependee_map(list(result.mapping.values()))

        for name, candidate in result.mapping.items():
            # Check whether the candidate was skipped
            if isinstance(candidate, SkippedCandidate):
                deps.append(SkippedDependency(candidate.name, candidate.skip_reason))
                continue

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

            dependee_reqs = _dependee_reqs_for_candidate(candidate, dependee_map, reqs)
            deps.append(RequirementDependency(name, candidate.version, dependee_reqs=dependee_reqs))
        return deps


class ResolveLibResolverError(DependencyResolverError):
    """
    A `resolvelib`-specific `DependencyResolverError`.
    """

    pass


def _build_dependee_map(
    candidates: list[Candidate],
) -> dict[Requirement, list[Requirement]]:
    """
    Build a mapping of dependee `Requirement`s to dependers. This is needed to find the top-level
    requirements that each subdependency originates from.
    """
    dependee_map: dict[Requirement, list[Requirement]] = {}
    for c in candidates:
        if isinstance(c, SkippedCandidate):
            continue
        c = cast(ResolvedCandidate, c)
        for dep in c.dependencies:
            if dep not in dependee_map:
                dependee_map[dep] = []
            dependee_map[dep].extend(c.reqs)
    return dependee_map


def _dependee_reqs_for_candidate(
    candidate: ResolvedCandidate,
    dependee_map: dict[Requirement, list[Requirement]],
    reqs: list[Requirement],
) -> set[Requirement]:
    """
    Find the set of top-level `Requirement`s that a given candidate originates from.
    """
    # Make sure we don't get stuck in a loop if the requirements file has cyclical dependencies.
    seen: list[Requirement] = list()

    def find_dependees(req: Requirement) -> set[Requirement]:
        if req in seen:
            return set()
        if req in reqs:
            return {req}
        seen.append(req)
        dependees = set()
        for r in dependee_map[req]:
            dependees |= find_dependees(r)
        seen.pop()
        return dependees

    dependee_reqs = set()
    for req in candidate.reqs:
        dependee_reqs |= find_dependees(req)
    return dependee_reqs
