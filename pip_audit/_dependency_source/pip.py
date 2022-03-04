"""
Collect the local environment's active dependencies via `pip list`, wrapped
by `pip-api`.
"""

import logging
import subprocess
import sys
from pathlib import Path
from typing import Iterator, Sequence

import pip_api
from packaging.version import InvalidVersion, Version

from pip_audit._dependency_source import DependencyFixError, DependencySource, DependencySourceError
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency, ResolvedDependency, SkippedDependency
from pip_audit._state import AuditState

logger = logging.getLogger(__name__)

# Versions of `pip` prior to this version don't support `pip list -v --format=json`,
# which is our baseline for reliable output. We'll attempt to use versions before
# this one, but not before complaining about it.
_MINIMUM_RELIABLE_PIP_VERSION = Version("10.0.0b0")

# NOTE(ww): The round-trip assignment here is due to type confusion: `pip_api.PIP_VERSION`
# is a `Version` object, but it's a `pip_api._vendor.packaging.version.Version` instead
# of a `packaging.version.Version`. Recreating the version with the correct type
# ensures that our comparison operators work as expected.
_PIP_VERSION = Version(str(pip_api.PIP_VERSION))


class PipSource(DependencySource):
    """
    Wraps `pip` (specifically `pip list`) as a dependency source.
    """

    def __init__(
        self,
        *,
        local: bool = False,
        paths: Sequence[Path] = [],
        skip_editable: bool = False,
        state: AuditState = AuditState(),
    ) -> None:
        """
        Create a new `PipSource`.

        `local` determines whether to do a "local-only" list. If `True`, the
        `DependencySource` does not expose globally installed packages.

        `paths` is a list of locations to look for installed packages. If the
        list is empty, the `DependencySource` will query the current Python
        environment.

        `skip_editable` controls whether dependencies marked as "editable" are skipped.
        By default, editable dependencies are not skipped.

        `state` is an `AuditState` to use for state callbacks.
        """
        self._local = local
        self._paths = paths
        self._skip_editable = skip_editable
        self.state = state

        if _PIP_VERSION < _MINIMUM_RELIABLE_PIP_VERSION:
            logger.warning(
                f"Warning: pip {_PIP_VERSION} is very old, and may not provide reliable "
                "dependency information! You are STRONGLY encouraged to upgrade to a "
                "newer version of pip."
            )

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `PipSource`.

        Raises a `PipSourceError` on any errors.
        """

        # The `pip list` call that underlies `pip_api` could fail for myriad reasons.
        # We collect them all into a single well-defined error.
        try:
            for (_, dist) in pip_api.installed_distributions(
                local=self._local, paths=list(self._paths)
            ).items():
                dep: Dependency
                if dist.editable and self._skip_editable:
                    dep = SkippedDependency(
                        name=dist.name, skip_reason="distribution marked as editable"
                    )
                else:
                    try:
                        dep = ResolvedDependency(name=dist.name, version=Version(str(dist.version)))
                        self.state.update_state(f"Collecting {dep.name} ({dep.version})")
                    except InvalidVersion:
                        skip_reason = (
                            "Package has invalid version and could not be audited: "
                            f"{dist.name} ({dist.version})"
                        )
                        logger.debug(skip_reason)
                        dep = SkippedDependency(name=dist.name, skip_reason=skip_reason)
                yield dep
        except Exception as e:
            raise PipSourceError("failed to list installed distributions") from e

    def fix(self, fix_version: ResolvedFixVersion) -> None:
        """
        Fixes a dependency version in this `PipSource`.
        """
        self.state.update_state(
            f"Fixing {fix_version.dep.name} ({fix_version.dep.version} => {fix_version.version})"
        )
        fix_cmd = [
            sys.executable,
            "-m",
            "pip",
            "install",
            f"{fix_version.dep.canonical_name}=={fix_version.version}",
        ]
        try:
            subprocess.run(
                fix_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as cpe:
            raise PipFixError(
                f"failed to upgrade dependency {fix_version.dep.name} to fix version "
                f"{fix_version.version}"
            ) from cpe


class PipSourceError(DependencySourceError):
    """A `pip` specific `DependencySourceError`."""

    pass


class PipFixError(DependencyFixError):
    """A `pip` specific `DependencyFixError`."""

    pass
