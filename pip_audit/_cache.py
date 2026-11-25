"""
Caching middleware for `pip-audit`.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, cast

import pip_api
import urllib3
from cachecontrol.caches import FileCache
from cachecontrol.controller import CacheController
from packaging.version import Version
from platformdirs import user_cache_path
from urllib3._collections import HTTPHeaderDict
from urllib3.response import BaseHTTPResponse
from urllib3.util import Retry

logger = logging.getLogger(__name__)

# The `cache dir` command was added to `pip` as of 20.1 so we should check before trying to use it
# to discover the `pip` HTTP cache
_MINIMUM_PIP_VERSION = Version("20.1")

_PIP_VERSION = Version(str(pip_api.PIP_VERSION))

_PIP_AUDIT_LEGACY_INTERNAL_CACHE = Path.home() / ".pip-audit-cache"


def _get_pip_cache() -> Path:
    # Unless the cache directory is specifically set by the `--cache-dir` option, we try to share
    # the `pip` HTTP cache
    cmd = [sys.executable, "-m", "pip", "cache", "dir"]
    try:
        process = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as cpe:  # pragma: no cover
        # NOTE: This should only happen if pip's cache has been explicitly disabled,
        # which we check for in the caller (via `PIP_NO_CACHE_DIR`).
        from pip_audit._service.interface import ServiceError

        raise ServiceError(f"Failed to query the `pip` HTTP cache directory: {cmd}") from cpe
    cache_dir = process.stdout.decode("utf-8").strip("\n")
    http_cache_dir = Path(cache_dir) / "http"
    return http_cache_dir


def _get_cache_dir(custom_cache_dir: Path | None, *, use_pip: bool = True) -> Path:
    """
    Returns a directory path suitable for HTTP caching.

    The directory is **not** guaranteed to exist.

    `use_pip` tells the function to prefer `pip`'s pre-existing cache,
    **unless** `PIP_NO_CACHE_DIR` is present in the environment.
    """

    # If the user has explicitly requested a directory, pass it through unscathed.
    if custom_cache_dir is not None:
        return custom_cache_dir

    # Retrieve pip-audit's default internal cache using `platformdirs`.
    pip_audit_cache_dir = user_cache_path("pip-audit", appauthor=False, ensure_exists=True)

    # If the retrieved cache isn't the legacy one, try to delete the old cache if it exists.
    if (
        _PIP_AUDIT_LEGACY_INTERNAL_CACHE.exists()
        and pip_audit_cache_dir != _PIP_AUDIT_LEGACY_INTERNAL_CACHE
    ):
        shutil.rmtree(_PIP_AUDIT_LEGACY_INTERNAL_CACHE)

    # Respect pip's PIP_NO_CACHE_DIR environment setting.
    if use_pip and not os.getenv("PIP_NO_CACHE_DIR"):
        pip_cache_dir = _get_pip_cache() if _PIP_VERSION >= _MINIMUM_PIP_VERSION else None
        if pip_cache_dir is not None:
            return pip_cache_dir
        else:
            logger.warning(
                f"pip {_PIP_VERSION} doesn't support the `cache dir` subcommand, "
                f"using {pip_audit_cache_dir} instead"
            )
            return pip_audit_cache_dir
    else:
        return pip_audit_cache_dir


class _SafeFileCache(FileCache):
    """
    A rough mirror of `pip`'s `SafeFileCache` that *should* be runtime-compatible
    with `pip` (i.e., does not interfere with `pip` when it shares the same
    caching directory as a running `pip` process).
    """

    def __init__(self, directory: Path):
        self._logged_warning = False
        super().__init__(str(directory))

    def get(self, key: str) -> Any | None:
        try:
            return super().get(key)
        except Exception as e:  # pragma: no cover
            if not self._logged_warning:
                logger.warning(
                    f"Failed to read from cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True
            return None

    def set(self, key: str, value: bytes, expires: Any | None = None) -> None:
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
        except OSError:  # pragma: no cover
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

        # NOTE(ww): Windows won't let us rename the temporary file until it's closed,
        # which is why we call `os.replace()` here rather than in the `with` block above.
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


@dataclass
class _CacheRequest:
    method: str
    url: str
    headers: HTTPHeaderDict


class _CachingPoolManager:
    def __init__(self, cache_dir: Path):
        self._pool = urllib3.PoolManager(
            retries=Retry(
                total=None,
                connect=False,
                read=False,
                redirect=5,
                other=False,
            )
        )
        self._controller = CacheController(_SafeFileCache(cache_dir))

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> BaseHTTPResponse:
        request_headers = HTTPHeaderDict(headers)
        cache_request = _CacheRequest(method, url, request_headers)

        if method != "GET":
            return self._pool.request(method, url, headers=request_headers, **kwargs)

        try:
            cached_response = self._controller.cached_request(cast(Any, cache_request))
        except zlib.error:
            cached_response = False

        if cached_response:
            return cached_response

        request_headers.update(self._controller.conditional_headers(cast(Any, cache_request)))
        response = self._pool.request(method, url, headers=request_headers, **kwargs)

        if response.status == 304:
            cached_response = self._controller.update_cached_response(
                cast(Any, cache_request), cast(Any, response)
            )
            response.release_conn()
            return cached_response

        self._controller.cache_response(
            cast(Any, cache_request), cast(Any, response), body=response.data
        )
        return response


def caching_session(cache_dir: Path | None, *, use_pip: bool = False) -> _CachingPoolManager:
    """
    Return an HTTP session with suitable caching middleware.

    Uses the given `cache_dir` for the HTTP cache.

    `use_pip` determines how the fallback cache directory is determined, if `cache_dir` is None.
    When `use_pip` is `False`, `caching_session` will use a `pip-audit` internal cache directory.
    When `use_pip` is `True`, `caching_session` will attempt to discover `pip`'s cache
    directory, falling back on the internal `pip-audit` cache directory if the user's
    version of `pip` is too old.
    """

    return _CachingPoolManager(_get_cache_dir(cache_dir, use_pip=use_pip))
