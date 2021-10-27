import logging
import os
import subprocess
import sys
from typing import Any, List, Optional

import requests
from cachecontrol import CacheControl  # type: ignore
from cachecontrol.caches import FileCache  # type: ignore
from packaging.version import InvalidVersion, Version

from .interface import Dependency, ServiceError, VulnerabilityResult, VulnerabilityService

logger = logging.getLogger(__name__)


class SafeFileCache(FileCache):
    def __init__(self, directory):
        self.logged_warning = False
        super().__init__(directory)

    def get(self, key: str) -> Optional[Any]:
        try:
            return super().get(key)
        except Exception as e:  # pragma: no cover
            if not self.logged_warning:
                logger.warning(
                    f"Failed to read from cache directory, performance may be degraded: {e}"
                )
                self.logged_warning = True
            return None

    def set(self, key: str, value: str) -> None:
        try:
            super().set(key, value)
        except Exception as e:  # pragma: no cover
            if not self.logged_warning:
                logger.warning(
                    f"Failed to write to cache directory, performance may be degraded: {e}"
                )
                self.logged_warning = True

    def delete(self, key: str) -> None:  # pragma: no cover
        try:
            super().delete(key)
        except Exception as e:
            if not self.logged_warning:
                logger.warning(
                    f"Failed to delete file from cache directory, performance may be degraded: {e}"
                )
                self.logged_warning = True


def _get_pip_cache() -> str:
    # If `pip` is in the `PATH`, let's try to reuse the `pip` HTTP cache
    cmd = [sys.executable, "-m", "pip", "cache", "dir"]
    try:
        process = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as cpe:
        raise ServiceError(f"Failed to query the `pip` HTTP cache directory: {cmd}") from cpe
    cache_dir = process.stdout.decode("utf-8")
    http_cache_dir = os.path.join(cache_dir, "http")
    return http_cache_dir


def _get_cached_session():
    return CacheControl(
        requests.Session(),
        cache=SafeFileCache(os.environ.get("PIP_AUDIT_CACHE", _get_pip_cache())),
    )


class PyPIService(VulnerabilityService):
    def __init__(self):
        self.session = _get_cached_session()

    def query(self, spec: Dependency) -> List[VulnerabilityResult]:
        url = f"https://pypi.org/pypi/{spec.package}/{str(spec.version)}/json"
        response: requests.Response = self.session.get(url=url)
        try:
            response.raise_for_status()
        except requests.HTTPError as http_error:
            raise ServiceError from http_error

        response_json = response.json()
        results: List[VulnerabilityResult] = []

        vulns = response_json.get("vulnerabilities")

        # No `vulnerabilities` key means that there are no vulnerabilities for any version
        if vulns is None:
            return results

        for v in vulns:
            # Put together the fix versions list
            try:
                fix_versions = [Version(fixed_in) for fixed_in in v["fixed_in"]]
            except InvalidVersion as iv:
                raise ServiceError(f'Received malformed version from PyPI: {v["fixed_in"]}') from iv

            # The ranges aren't guaranteed to come in chronological order
            fix_versions.sort()

            results.append(VulnerabilityResult(v["id"], v["details"], fix_versions))

        return results
