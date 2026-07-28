"""
Caching middleware for `pip-audit`.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import IO, Any

import pip_api
import requests
from cachecontrol import CacheControl
from cachecontrol.cache import SeparateBodyBaseCache
from cachecontrol.caches import FileCache, SeparateBodyFileCache
from packaging.version import Version
from platformdirs import user_cache_path

from pip_audit._service.interface import ServiceError

logger = logging.getLogger(__name__)

# The `cache dir` command was added to `pip` as of 20.1 so we should check before trying to use it
# to discover the `pip` HTTP cache
_MINIMUM_PIP_VERSION = Version("20.1")

# `pip` 23.3 (https://github.com/pypa/pip/pull/11143) switched its HTTP cache from a
# single combined (header + body) file per entry, stored under an `http` directory, to
# `http-v2`: a format that stores each entry's response body separately from its
# metadata. `pip` never writes to `http` once it's past this version, so we need to
# know which format the installed `pip` actually uses in order to keep sharing a warm,
# readable cache with it. See `_SafeFileCache` and `_LegacySafeFileCache`.
_MINIMUM_PIP_HTTP_V2_VERSION = Version("23.3")

_PIP_VERSION = Version(str(pip_api.PIP_VERSION))

_PIP_AUDIT_LEGACY_INTERNAL_CACHE = Path.home() / ".pip-audit-cache"

# Matches `cachecontrol.caches.file_cache._FileCacheMixin`'s default `dirmode`.
_CACHE_DIR_MODE = 0o0700


def _atomic_write(path: str, value: bytes) -> None:
    """
    Write `value` to `path`, creating parent directories as needed.

    We don't want to use lock files since `pip` isn't going to recognise those. We should
    write to the cache in a similar way to how `pip` does it. We create a temporary file,
    then atomically replace the actual cache key's filename with it. This ensures
    that other concurrent `pip` or `pip-audit` instances don't read partial data.
    """

    # Make sure the directory exists
    try:
        os.makedirs(os.path.dirname(path), _CACHE_DIR_MODE)
    except OSError:  # pragma: no cover
        pass

    with NamedTemporaryFile(delete=False, dir=os.path.dirname(path)) as io:
        io.write(value)

        # NOTE(ww): Similar to what `pip` does in `adjacent_tmp_file`.
        io.flush()
        os.fsync(io.fileno())

    # NOTE(ww): Windows won't let us rename the temporary file until it's closed,
    # which is why we call `os.replace()` here rather than in the `with` block above.
    os.replace(io.name, path)


def _get_pip_cache() -> tuple[Path, bool]:
    """
    Returns `pip`'s HTTP cache directory, and whether that directory uses `pip`'s
    legacy (pre-23.3) single-file cache format rather than the current `http-v2`
    format (see `_MINIMUM_PIP_HTTP_V2_VERSION`).
    """

    # Unless the cache directory is specifically set by the `--cache-dir` option, we try to share
    # the `pip` HTTP cache
    cmd = [sys.executable, "-m", "pip", "cache", "dir"]
    try:
        process = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as cpe:  # pragma: no cover
        # NOTE: This should only happen if pip's cache has been explicitly disabled,
        # which we check for in the caller (via `PIP_NO_CACHE_DIR`).
        raise ServiceError(f"Failed to query the `pip` HTTP cache directory: {cmd}") from cpe
    cache_dir = Path(process.stdout.decode("utf-8").strip("\n"))

    if _PIP_VERSION >= _MINIMUM_PIP_HTTP_V2_VERSION:
        return cache_dir / "http-v2", False
    return cache_dir / "http", True


def _get_cache_dir(custom_cache_dir: Path | None, *, use_pip: bool = True) -> tuple[Path, bool]:
    """
    Returns a directory path suitable for HTTP caching, and whether that directory
    uses `pip`'s legacy (pre-23.3) single-file cache format rather than the current
    `http-v2` format (see `_MINIMUM_PIP_HTTP_V2_VERSION`).

    The directory is **not** guaranteed to exist.

    `use_pip` tells the function to prefer `pip`'s pre-existing cache,
    **unless** `PIP_NO_CACHE_DIR` is present in the environment.
    """

    # If the user has explicitly requested a directory, pass it through unscathed. It isn't
    # shared with any particular `pip` version, so we always use the current cache format
    # for it.
    if custom_cache_dir is not None:
        return custom_cache_dir, False

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
        if _PIP_VERSION >= _MINIMUM_PIP_VERSION:
            return _get_pip_cache()
        else:
            logger.warning(
                f"pip {_PIP_VERSION} doesn't support the `cache dir` subcommand, "
                f"using {pip_audit_cache_dir} instead"
            )
            return pip_audit_cache_dir, False
    else:
        return pip_audit_cache_dir, False


class _SafeFileCache(SeparateBodyBaseCache):
    """
    A rough mirror of `pip`'s current `SafeFileCache` that *should* be runtime-compatible
    with `pip` (i.e., does not interfere with `pip` when it shares the same
    caching directory as a running `pip` process).

    `pip` 23.3 (https://github.com/pypa/pip/pull/11143) moved to storing each cache
    entry's response body separately from its metadata (in an adjacent `.body` file),
    reducing peak memory usage. This is `pip`'s `http-v2` cache format; see
    `_LegacySafeFileCache` for the format used by `pip` versions older than 23.3.
    """

    def __init__(self, directory: Path):
        self._logged_warning = False
        self._directory = str(directory)

    def _get_cache_path(self, key: str) -> str:
        # From `cachecontrol.caches.file_cache.SeparateBodyFileCache.encode`/`_fn`,
        # brought into our class for backwards-compatibility and to avoid using a
        # non-public method. This mirrors `pip`'s own `SafeFileCache._get_cache_path`.
        hashed = SeparateBodyFileCache.encode(key)
        parts = list(hashed[:5]) + [hashed]
        return os.path.join(self._directory, *parts)

    def _warn_once(self, message: str) -> None:
        if not self._logged_warning:
            logger.warning(message)
            self._logged_warning = True

    def get(self, key: str) -> bytes | None:
        # The cache entry is only valid if both the metadata and the body are present,
        # mirroring `pip`'s own `SafeFileCache.get`. This also means that an entry
        # written by `_LegacySafeFileCache` (which never writes a `.body` file) is
        # always treated as a miss here, rather than misread as `http-v2` metadata.
        metadata_path = self._get_cache_path(key)
        body_path = metadata_path + ".body"
        if not (os.path.exists(metadata_path) and os.path.exists(body_path)):
            return None

        try:
            with open(metadata_path, "rb") as f:
                return f.read()
        except Exception as e:  # pragma: no cover
            self._warn_once(
                f"Failed to read from cache directory, performance may be degraded: {e}"
            )
            return None

    def get_body(self, key: str) -> IO[bytes] | None:
        metadata_path = self._get_cache_path(key)
        body_path = metadata_path + ".body"
        if not (os.path.exists(metadata_path) and os.path.exists(body_path)):
            return None

        try:
            return open(body_path, "rb")
        except Exception as e:  # pragma: no cover
            self._warn_once(
                f"Failed to read from cache directory, performance may be degraded: {e}"
            )
            return None

    def set(self, key: str, value: bytes, expires: int | datetime | None = None) -> None:
        try:
            _atomic_write(self._get_cache_path(key), value)
        except Exception as e:  # pragma: no cover
            self._warn_once(f"Failed to write to cache directory, performance may be degraded: {e}")

    def set_body(self, key: str, body: bytes) -> None:
        try:
            _atomic_write(self._get_cache_path(key) + ".body", body)
        except Exception as e:  # pragma: no cover
            self._warn_once(f"Failed to write to cache directory, performance may be degraded: {e}")

    def _remove(self, path: str) -> None:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    def delete(self, key: str) -> None:  # pragma: no cover
        try:
            metadata_path = self._get_cache_path(key)
            self._remove(metadata_path)
            self._remove(metadata_path + ".body")
        except Exception as e:
            self._warn_once(
                f"Failed to delete file from cache directory, performance may be degraded: {e}"
            )


class _LegacySafeFileCache(FileCache):
    """
    A rough mirror of `pip`'s pre-23.3 `SafeFileCache`, which stores each cache entry
    as a single combined (header + body) file. `pip` 23.3
    (https://github.com/pypa/pip/pull/11143) replaced this format with `http-v2` (see
    `_SafeFileCache`); we keep this implementation around so that we can still share a
    warm cache with installations of `pip` older than 23.3, which never write to
    `http-v2`.
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
            _atomic_write(super()._fn(key), value)
        except Exception as e:  # pragma: no cover
            if not self._logged_warning:
                logger.warning(
                    f"Failed to write to cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True

    def delete(self, key: str) -> None:  # pragma: no cover
        try:
            super().delete(key)
        except Exception as e:
            if not self._logged_warning:
                logger.warning(
                    f"Failed to delete file from cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True


def caching_session(cache_dir: Path | None, *, use_pip: bool = False) -> requests.Session:
    """
    Return a `requests` style session, with suitable caching middleware.

    Uses the given `cache_dir` for the HTTP cache.

    `use_pip` determines how the fallback cache directory is determined, if `cache_dir` is None.
    When `use_pip` is `False`, `caching_session` will use a `pip-audit` internal cache directory.
    When `use_pip` is `True`, `caching_session` will attempt to discover `pip`'s cache
    directory, falling back on the internal `pip-audit` cache directory if the user's
    version of `pip` is too old.

    The on-disk cache format used is whichever format the resolved directory's `pip`
    (if any) actually uses: `http-v2` (`_SafeFileCache`) for `pip` >= 23.3, or the
    legacy single-file format (`_LegacySafeFileCache`) for older `pip` versions.
    """

    # We limit the number of redirects to 5, since the services we connect to
    # should really never redirect more than once or twice.
    inner_session = requests.Session()
    inner_session.max_redirects = 5

    resolved_cache_dir, use_legacy_format = _get_cache_dir(cache_dir, use_pip=use_pip)
    cache: SeparateBodyBaseCache | FileCache
    if use_legacy_format:
        cache = _LegacySafeFileCache(resolved_cache_dir)
    else:
        cache = _SafeFileCache(resolved_cache_dir)

    return CacheControl(inner_session, cache=cache)
