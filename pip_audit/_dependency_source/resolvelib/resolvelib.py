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

from pip_audit._dependency_source import DependencyResolver, DependencyResolverError
from pip_audit._dependency_source.requirement import RequirementDependency
from pip_audit._service.interface import Dependency, SkippedDependency
from pip_audit._state import AuditState

from .pypi_provider import Candidate, PyPIProvider

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

    def resolve(self, reqs: list[Requirement]) -> list[Dependency]:
        """
        Resolve the given `Requirement` into a `Dependency` list.
        """

        deps: list[Dependency] = []

        reqs_to_resolve: list[Requirement] = []
        for req in reqs:
            # HACK: `resolve` takes both `packaging.Requirement` and `pip_api.Requirement`,
            # since the latter is a subclass. But only the latter knows whether the
            # requirement is editable, so we need to check for it here.
            if isinstance(req, ParsedRequirement):
                if req.editable and self._skip_editable:
                    deps.append(
                        SkippedDependency(
                            name=req.name, skip_reason="requirement marked as editable"
                        )
                    )
                continue
            reqs_to_resolve.append(req)

        try:
            result = self.resolver.resolve(reqs_to_resolve)
        except HTTPError as e:
            raise ResolveLibResolverError("failed to resolve dependencies") from e

        # If the provider encountered any dependencies it couldn't find on PyPI, they'll be here.
        deps.extend(self.provider.skip_deps)

        # Construct dependee mapping to figure out what top-level requirements correspond to what
        # dependencies.
        dependee_map = _build_dependee_map(result.mapping.values())

        for name, candidate in result.mapping.items():
            origin_reqs = _find_origin_reqs(candidate, dependee_map, reqs)
            deps.append(RequirementDependency(name, candidate.version, origin_reqs=origin_reqs))
        return deps


class ResolveLibResolverError(DependencyResolverError):
    """
    A `resolvelib`-specific `DependencyResolverError`.
    """

    pass


def _build_dependee_map(candidates: list[Candidate]) -> dict[_Requirement, list[_Requirement]]:
    """
    Build a mapping of dependee `Requirement`s to dependers. This is needed to find the top-level
    requirements that each subdependency originates from.
    """
    dependee_map = {}
    for c in candidates:
        for dep in c.dependencies:
            if dep not in dependee_map:
                dependee_map[dep] = []
            dependee_map[dep].extend(c.reqs)
    return dependee_map


def _find_origin_reqs(
    candidate: Candidate,
    dependee_map: dict[_Requirement, list[_Requirement]],
    reqs: list[_Requirement],
) -> set[_Requirement]:
    """
    Find the set of top-level `Requirement`s that a given candidate originates from.
    """
    # Make sure we don't get stuck in a loop if the requirements file has cyclical dependencies.
    seen: list[_Requirement] = list()

    def find_dependees(req: _Requirement) -> set[_Requirement]:
        if req in seen:
            return set()
        if req in reqs:
            return {req}
        seen.append(req)
        if req in dependee_map:
            dependees = set()
            for r in dependee_map[req]:
                dependees |= find_dependees(r)
            return dependees
        seen.pop()
        return set()

    origin_reqs = set()
    for req in candidate.reqs:
        origin_reqs |= find_dependees(req)
    return origin_reqs
