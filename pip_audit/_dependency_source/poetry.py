"""
Collect dependencies from `poetry.lock` files.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import toml
from packaging.version import InvalidVersion, Version

from pip_audit._dependency_source import DependencyFixError, DependencySource
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency, ResolvedDependency, SkippedDependency

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PoetrySource(DependencySource):
    """
    Dependency sourcing from `poetry.lock`.
    """

    path: Path

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `PoetrySource`.
        """
        with self.path.open("r") as stream:
            packages = toml.load(stream)
        for package in packages["package"]:
            name = package["name"]
            try:
                version = Version(package["version"])
            except InvalidVersion:
                skip_reason = (
                    "Package has invalid version and could not be audited: "
                    f"{name} ({package['version']})"
                )
                yield SkippedDependency(name=name, skip_reason=skip_reason)
            else:
                yield ResolvedDependency(name=name, version=version)

    def fix(self, fix_version: ResolvedFixVersion) -> None:
        """
        Fixes a dependency version for this `PoetrySource`.

        Requires poetry to be installed in the same env.

        Note that poetry ignores the version we want to update to,
        and goes straight to the latest version allowed in metadata.
        """
        raise DependencyFixError("fix is not supported for poetry yet")  # pragma: no cover
