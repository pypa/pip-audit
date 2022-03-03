"""
Collect dependencies from `pyproject.toml` files.
"""

import logging
from pathlib import Path
from typing import Iterator, List, Set, cast

import toml
from packaging.requirements import Requirement

from pip_audit._dependency_source import (
    DependencyFixError,
    DependencyResolver,
    DependencyResolverError,
    DependencySource,
    DependencySourceError,
)
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency
from pip_audit._service.interface import ResolvedDependency, SkippedDependency
from pip_audit._state import AuditState

logger = logging.getLogger(__name__)


class PyProjectSource(DependencySource):
    """
    Wraps `pyproject.toml` dependency resolution as a dependency source.
    """

    def __init__(
        self, filename: Path, resolver: DependencyResolver, state: AuditState = AuditState()
    ) -> None:
        self.filename = filename
        self.resolver = resolver
        self.state = state

    def collect(self) -> Iterator[Dependency]:
        collected: Set[Dependency] = set()
        with open(self.filename, "r") as f:
            pyproject_data = toml.load(f)
            if "project" not in pyproject_data:
                raise PyProjectSourceError(
                    f"pyproject file {self.filename} does not contain `project` section"
                )
            project = pyproject_data["project"]
            if "dependencies" not in project:
                # Projects without dependencies aren't an error case
                logger.warn(f"pyproject file {self.filename} does not contain `dependencies` list")
                return
            deps = project["dependencies"]
            reqs: List[Requirement] = [Requirement(dep) for dep in deps]
            try:
                for _, deps in self.resolver.resolve_all(iter(reqs)):
                    for dep in deps:
                        # Don't allow duplicate dependencies to be returned
                        if dep in collected:
                            continue

                        if dep.is_skipped():  # pragma: no cover
                            dep = cast(SkippedDependency, dep)
                            self.state.update_state(f"Skipping {dep.name}: {dep.skip_reason}")
                        else:
                            dep = cast(ResolvedDependency, dep)
                            self.state.update_state(f"Collecting {dep.name} ({dep.version})")

                        collected.add(dep)
                        yield dep
            except DependencyResolverError as dre:
                raise PyProjectSourceError("dependency resolver raised an error") from dre

    def fix(self, fix_version: ResolvedFixVersion) -> None:
        raise NotImplementedError


class PyProjectSourceError(DependencySourceError):
    pass


class PyProjectFixError(DependencyFixError):
    pass
