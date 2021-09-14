"""
Collect the local environment's active dependencies via `pip list`, wrapped
by `pip-api`.
"""

import logging
from typing import Iterator

import pip_api
from packaging.version import Version

from pip_audit.dependency_source import DependencySource, DependencySourceError
from pip_audit.service import Dependency

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
    def __init__(self):
        if _PIP_VERSION < _MINIMUM_RELIABLE_PIP_VERSION:
            logger.warning(
                f"Warning: pip {_PIP_VERSION} is very old, and may not provide reliable "
                "dependency information! You are STRONGLY encouraged to upgrade to a "
                "newer version of pip."
            )

    def collect(self) -> Iterator[Dependency]:
        # The `pip list` call that underlies `pip_api` could fail for myriad reasons.
        # We collect them all into a single well-defined error.
        try:
            for (_, dist) in pip_api.installed_distributions().items():
                yield Dependency(package=dist.name, version=Version(str(dist.version)))
        except Exception as e:
            raise PipSourceError("failed to list installed distributions") from e


class PipSourceError(DependencySourceError):
    pass
