from pathlib import Path

import pretend  # type: ignore
from packaging.version import Version

import pip_audit._cache as cache
from pip_audit._cache import _get_cache_dir


def test_get_cache_dir(monkeypatch):
    # When we supply a cache directory, always use that
    cache_dir = _get_cache_dir(Path("/tmp/foo/cache_dir"))
    assert str(cache_dir) == "/tmp/foo/cache_dir"

    get_pip_cache = pretend.call_recorder(lambda: "/fake/pip/cache/dir")
    monkeypatch.setattr(cache, "_get_pip_cache", get_pip_cache)

    cache_dir = _get_cache_dir(None)
    assert str(cache_dir) == "/fake/pip/cache/dir"


def test_get_cache_dir_old_pip(monkeypatch):
    # Check the case where we have an old `pip`
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("1.0.0"))

    # When we supply a cache directory, always use that
    cache_dir = _get_cache_dir(Path("/tmp/foo/cache_dir"))
    assert str(cache_dir) == "/tmp/foo/cache_dir"

    # Mock out home since this is going to be different across systems
    class MockPath:
        @staticmethod
        def home():
            return Path("/Users/foo")

    # In this case, we can't query `pip` to figure out where its HTTP cache is
    # Instead, we use `~/.pip-audit-cache`
    monkeypatch.setattr(cache, "Path", MockPath)

    cache_dir = _get_cache_dir(None)
    assert str(cache_dir) == "/Users/foo/.pip-audit-cache"


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
