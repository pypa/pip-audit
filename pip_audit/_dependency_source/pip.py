"""
Collect the local environment's active dependencies via `pip list`, wrapped
by `pip-api`.
"""

import logging
from typing import Iterator, Optional

import pip_api
from packaging.version import InvalidVersion, Version

from pip_audit._dependency_source import DependencySource, DependencySourceError
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

    def __init__(self, *, local: bool = False, state: Optional[AuditState] = None) -> None:
        """
        Create a new `PipSource`.

        `local` determines whether to do a "local-only" list. If `True`, the
        `DependencySource` does not expose globally installed packages.

        `state` is an optional `AuditState` to use for state callbacks.
        """
        self._local = local
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
            for (_, dist) in pip_api.installed_distributions(local=self._local).items():
                dep: Dependency
                try:
                    dep = ResolvedDependency(name=dist.name, version=Version(str(dist.version)))
                    if self.state is not None:
                        self.state.update_state(
                            f"Collecting {dep.name} ({dep.version})"
                        )  # pragma: no cover
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


class PipSourceError(DependencySourceError):
    """A `pip` specific `DependencySourceError`."""

    pass
