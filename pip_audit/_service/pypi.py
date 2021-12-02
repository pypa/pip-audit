"""
Functionality for using the [PyPI](https://warehouse.pypa.io/api-reference/json.html)
API as a `VulnerabilityService`.
"""

import logging
import os
import subprocess
import sys
from pathlib import Path
from subprocess import run
from tempfile import NamedTemporaryFile
from typing import Any, List, Optional, Tuple, cast

import pip_api
import requests
from cachecontrol import CacheControl  # type: ignore
from cachecontrol.caches import FileCache  # type: ignore
from packaging.version import InvalidVersion, Version

from .interface import (
    Dependency,
    ResolvedDependency,
    ServiceError,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)

logger = logging.getLogger(__name__)

# The `cache dir` command was added to `pip` as of 20.1 so we should check before trying to use it
# to discover the `pip` HTTP cache
_MINIMUM_PIP_VERSION = Version("20.1")

_PIP_VERSION = Version(str(pip_api.PIP_VERSION))


class _SafeFileCache(FileCache):
    def __init__(self, directory):
        self._logged_warning = False
        super().__init__(directory)

    def get(self, key: str) -> Optional[Any]:
        try:
            return super().get(key)
        except Exception as e:  # pragma: no cover
            if not self._logged_warning:
                logger.warning(
                    f"Failed to read from cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True
            return None

    def set(self, key: str, value: bytes, expires: Optional[Any] = None) -> None:
        try:
            self._set_impl(key, value)
        except Exception as e:  # pragma: no cover
            if not self._logged_warning:
                logger.warning(
                    f"Failed to write to cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True

    def _set_impl(self, key: str, value: bytes) -> None:
        name: str = super()._fn(key)

        # Make sure the directory exists
        try:
            os.makedirs(os.path.dirname(name), self.dirmode)
        except (IOError, OSError):  # pragma: no cover
            pass

        # We don't want to use lock files since `pip` isn't going to recognise those. We should
        # write to the cache in a similar way to how `pip` does it. We create a temporary file,
        # then atomically replace the actual cache key's filename with it. This ensures
        # that other concurrent `pip` or `pip-audit` instances don't read partial data.
        with NamedTemporaryFile(delete=False, dir=os.path.dirname(name)) as io:
            io.write(value)

            # NOTE(ww): Similar to what `pip` does in `adjacent_tmp_file`.
            io.flush()
            os.fsync(io.fileno())

            os.replace(io.name, name)

    def delete(self, key: str) -> None:  # pragma: no cover
        try:
            super().delete(key)
        except Exception as e:
            if not self._logged_warning:
                logger.warning(
                    f"Failed to delete file from cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True


def _get_pip_cache() -> str:
    # Unless the cache directory is specifically set by the `--cache-dir` option, we try to share
    # the `pip` HTTP cache
    cmd = [sys.executable, "-m", "pip", "cache", "dir"]
    try:
        process = run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as cpe:  # pragma: no cover
        raise ServiceError(f"Failed to query the `pip` HTTP cache directory: {cmd}") from cpe
    cache_dir = process.stdout.decode("utf-8").strip("\n")
    http_cache_dir = os.path.join(cache_dir, "http")
    return http_cache_dir


def _get_cache_dir(custom_cache_dir: Optional[Path]) -> str:
    if custom_cache_dir is not None:
        return str(custom_cache_dir)

    pip_cache_dir = _get_pip_cache() if _PIP_VERSION >= _MINIMUM_PIP_VERSION else None
    if pip_cache_dir is not None:  # pragma: no cover
        return pip_cache_dir
    else:
        fallback_path = os.path.join(Path.home(), ".pip-audit-cache")
        logger.warning(
            f"Warning: pip {_PIP_VERSION} doesn't support the `cache dir` subcommand, unable to "
            f'reuse the `pip` HTTP cache and using "{fallback_path}" instead'
        )
        return fallback_path


def _get_cached_session(cache_dir: Optional[Path]):
    return CacheControl(requests.Session(), cache=_SafeFileCache(_get_cache_dir(cache_dir)))


class PyPIService(VulnerabilityService):
    """
    An implementation of `VulnerabilityService` that uses PyPI to provide Python
    package vulnerability information.
    """

    def __init__(self, cache_dir: Optional[Path] = None, timeout: Optional[int] = None) -> None:
        """
        Create a new `PyPIService`.

        `cache_dir` is an optional cache directory to use, for caching and reusing PyPI API
        requests. If `None`, `pip-audit` will attempt to use `pip`'s cache directory before falling
        back on its own default cache directory.
        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.
        """
        self.session = _get_cached_session(cache_dir)
        self.timeout = timeout

    def query(self, spec: Dependency) -> Tuple[Dependency, List[VulnerabilityResult]]:
        """
        Queries PyPI for the given `Dependency` specification.

        See `VulnerabilityService.query`.
        """
        if spec.is_skipped():
            return spec, []
        spec = cast(ResolvedDependency, spec)

        url = f"https://pypi.org/pypi/{spec.canonical_name}/{str(spec.version)}/json"
        response: requests.Response = self.session.get(url=url, timeout=self.timeout)
        try:
            response.raise_for_status()
        except requests.HTTPError as http_error:
            if response.status_code == 404:
                skip_reason = (
                    "Dependency not found on PyPI and could not be audited: "
                    f"{spec.canonical_name} ({spec.version})"
                )
                logger.debug(skip_reason)
                return SkippedDependency(name=spec.name, skip_reason=skip_reason), []
            raise ServiceError from http_error

        response_json = response.json()
        results: List[VulnerabilityResult] = []

        vulns = response_json.get("vulnerabilities")

        # No `vulnerabilities` key means that there are no vulnerabilities for any version
        if vulns is None:
            return spec, results

        for v in vulns:
            # Put together the fix versions list
            try:
                fix_versions = [Version(fixed_in) for fixed_in in v["fixed_in"]]
            except InvalidVersion as iv:
                raise ServiceError(f'Received malformed version from PyPI: {v["fixed_in"]}') from iv

            # The ranges aren't guaranteed to come in chronological order
            fix_versions.sort()

            results.append(VulnerabilityResult(v["id"], v["details"], fix_versions))

        return spec, results
