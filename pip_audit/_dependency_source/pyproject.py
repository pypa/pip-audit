"""
Collect dependencies from `pyproject.toml` files.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterator, cast

import toml
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

from pip_audit._dependency_source import (
    DependencyFixError,
    DependencyResolver,
    DependencyResolverError,
    DependencySource,
    DependencySourceError,
)
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency, ResolvedDependency, SkippedDependency
from pip_audit._state import AuditState

logger = logging.getLogger(__name__)


class PyProjectSource(DependencySource):
    """
    Wraps `pyproject.toml` dependency resolution as a dependency source.
    """

    def __init__(
        self, filename: Path, resolver: DependencyResolver, state: AuditState = AuditState()
    ) -> None:
        """
        Create a new `PyProjectSource`.

        `filename` provides a path to a `pyproject.toml` file

        `resolver` is the `DependencyResolver` to use.

        `state` is an `AuditState` to use for state callbacks.
        """
        self.filename = filename
        self.resolver = resolver
        self.state = state

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `PyProjectSource`.

        Raises a `PyProjectSourceError` on any errors.
        """

        collected: set[Dependency] = set()
        with self.filename.open("r") as f:
            pyproject_data = toml.load(f)

            project = pyproject_data.get("project")
            if project is None:
                raise PyProjectSourceError(
                    f"pyproject file {self.filename} does not contain `project` section"
                )

            deps = project.get("dependencies")
            if deps is None:
                # Projects without dependencies aren't an error case
                logger.warning(
                    f"pyproject file {self.filename} does not contain `dependencies` list"
                )
                return

            reqs: list[Requirement] = [Requirement(dep) for dep in deps]
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
        """
        Fixes a dependency version for this `PyProjectSource`.
        """

        with self.filename.open("r+") as f, NamedTemporaryFile(mode="r+", delete=False) as tmp:
            pyproject_data = toml.load(f)

            project = pyproject_data.get("project")
            if project is None:
                raise PyProjectFixError(
                    f"pyproject file {self.filename} does not contain `project` section"
                )

            deps = project.get("dependencies")
            if deps is None:
                # Projects without dependencies aren't an error case
                logger.warning(
                    f"pyproject file {self.filename} does not contain `dependencies` list"
                )
                return

            reqs = [Requirement(dep) for dep in deps]
            for i in range(len(reqs)):
                # When we find a requirement that matches the provided fix version, we need to edit
                # the requirement's specifier and then write it back to the underlying TOML data.
                req = reqs[i]
                if (
                    req.name == fix_version.dep.name
                    and req.specifier.contains(fix_version.dep.version)
                    and not req.specifier.contains(fix_version.version)
                ):
                    req.specifier = SpecifierSet(f"=={fix_version.version}")
                    deps[i] = str(req)
                assert req.marker is None or req.marker.evaluate()

            # Now dump the new edited TOML to the temporary file.
            toml.dump(pyproject_data, tmp)

            # And replace the original `pyproject.toml` file.
            os.replace(tmp.name, self.filename)


class PyProjectSourceError(DependencySourceError):
    """A `pyproject.toml` specific `DependencySourceError`."""

    pass


class PyProjectFixError(DependencyFixError):
    """A `pyproject.toml` specific `DependencyFixError`."""

    pass
