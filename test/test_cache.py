import importlib
import sys
from pathlib import Path

import platformdirs
import pretend  # type: ignore
import pytest
from packaging.version import Version
from pytest import MonkeyPatch

import pip_audit._cache as cache
from pip_audit._cache import _delete_legacy_cache_dir, _get_cache_dir, _get_pip_cache


def _patch_platformdirs(monkeypatch: MonkeyPatch, sys_platform: str) -> None:
    """Utility function to patch `platformdirs` in order to test cross-platforms."""
    # Mocking OS host
    monkeypatch.setattr(sys, "platform", sys_platform)
    # We are forced to reload `platformdirs` to get the correct cache directory
    # as cache definition is stored in the top level `__init__.py` file of the
    # `platformdirs` package
    importlib.reload(platformdirs)
    if sys_platform == "win32":
        monkeypatch.setenv("LOCALAPPDATA", "/tmp/AppData/Local")


def test_get_cache_dir(monkeypatch):
    # When we supply a cache directory, always use that
    cache_dir = _get_cache_dir(Path("/tmp/foo/cache_dir"))
    assert cache_dir.as_posix() == "/tmp/foo/cache_dir"

    get_pip_cache = pretend.call_recorder(lambda: Path("/fake/pip/cache/dir"))
    monkeypatch.setattr(cache, "_get_pip_cache", get_pip_cache)

    # When `pip cache dir` works, we use it. In this case, it's mocked.
    cache_dir = _get_cache_dir(None, use_pip=True)
    assert cache_dir.as_posix() == "/fake/pip/cache/dir"


def test_get_pip_cache():
    # Actually running `pip cache dir` gets us some path that ends with "http"
    cache_dir = _get_pip_cache()
    assert cache_dir.stem == "http"


@pytest.mark.parametrize(
    "sys_platform,expected",
    [
        pytest.param(
            "linux",
            Path.home() / ".cache" / "pip-audit",
            id="on Linux",
        ),
        pytest.param(
            "win32",
            Path("/tmp") / "AppData" / "Local" / "pip-audit" / "Cache",
            id="on Windows",
        ),
        pytest.param(
            "darwin",
            Path.home() / "Library" / "Caches" / "pip-audit",
            id="on MacOS",
        ),
    ],
)
def test_get_cache_dir_do_not_use_pip(monkeypatch, sys_platform, expected):
    # Check cross-platforms
    _patch_platformdirs(monkeypatch, sys_platform)
    # Even with None, we never use the pip cache if we're told not to.
    cache_dir = _get_cache_dir(None, use_pip=False)
    assert cache_dir == expected


@pytest.mark.parametrize(
    "sys_platform,expected",
    [
        pytest.param(
            "linux",
            Path.home() / ".cache" / "pip-audit",
            id="on Linux",
        ),
        pytest.param(
            "win32",
            Path("/tmp") / "AppData" / "Local" / "pip-audit" / "Cache",
            id="on Windows",
        ),
        pytest.param(
            "darwin",
            Path.home() / "Library" / "Caches" / "pip-audit",
            id="on MacOS",
        ),
    ],
)
def test_get_cache_dir_pip_disabled_in_environment(monkeypatch, sys_platform, expected):
    monkeypatch.setenv("PIP_NO_CACHE_DIR", "1")
    # Check cross-platforms
    _patch_platformdirs(monkeypatch, sys_platform)

    # Even with use_pip=True, we avoid pip's cache if the environment tells us to.
    assert _get_cache_dir(None, use_pip=True) == expected


@pytest.mark.parametrize(
    "sys_platform,expected",
    [
        pytest.param(
            "linux",
            Path.home() / ".cache" / "pip-audit",
            id="on Linux",
        ),
        pytest.param(
            "win32",
            Path("/tmp") / "AppData" / "Local" / "pip-audit" / "Cache",
            id="on Windows",
        ),
        pytest.param(
            "darwin",
            Path.home() / "Library" / "Caches" / "pip-audit",
            id="on MacOS",
        ),
    ],
)
def test_get_cache_dir_old_pip(monkeypatch, sys_platform, expected):
    # Check the case where we have an old `pip`
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("1.0.0"))
    # Check cross-platforms
    _patch_platformdirs(monkeypatch, sys_platform)

    # When we supply a cache directory, always use that
    cache_dir = _get_cache_dir(Path("/tmp/foo/cache_dir"))
    assert cache_dir.as_posix() == "/tmp/foo/cache_dir"

    # In this case, we can't query `pip` to figure out where its HTTP cache is
    # Instead, we use `~/.pip-audit-cache`
    cache_dir = _get_cache_dir(None)
    assert cache_dir == expected


def test_cache_warns_about_old_pip(monkeypatch, cache_dir):
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("1.0.0"))
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(cache, "logger", logger)

    # If we supply a cache directory, we're not relying on finding the `pip` cache so no need to log
    # a warning
    _get_cache_dir(cache_dir)
    assert len(logger.warning.calls) == 0

    # However, if we're not specifying a cache directory, we'll try to call `pip cache dir`. If we
    # have an old `pip`, then we should expect a warning to be logged
    _get_cache_dir(None)
    assert len(logger.warning.calls) == 1


def test_delete_legacy_cache_dir(tmp_path):
    legacy = tmp_path / "pip-audit-cache"
    legacy.mkdir()
    assert legacy.exists()

    current = _get_cache_dir(None, use_pip=False)
    _delete_legacy_cache_dir(current, legacy)
    assert not legacy.exists()
