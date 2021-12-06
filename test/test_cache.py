from pathlib import Path

import pretend  # type: ignore
from packaging.version import Version

import pip_audit._cache as cache
from pip_audit._cache import _get_cache_dir, _get_pip_cache


def test_get_cache_dir(monkeypatch):
    # When we supply a cache directory, always use that
    cache_dir = _get_cache_dir(Path("/tmp/foo/cache_dir"))
    assert str(cache_dir) == "/tmp/foo/cache_dir"

    get_pip_cache = pretend.call_recorder(lambda: "/fake/pip/cache/dir")
    monkeypatch.setattr(cache, "_get_pip_cache", get_pip_cache)

    # When `pip cache dir` works, we use it. In this case, it's mocked.
    cache_dir = _get_cache_dir(None, use_pip=True)
    assert str(cache_dir) == "/fake/pip/cache/dir"


def test_get_pip_cache():
    # Actually running `pip cache dir` gets us some path that ends with "http"
    cache_dir = _get_pip_cache()
    assert cache_dir.stem == "http"


def test_get_cache_dir_do_not_use_pip():
    # Even with None, we never use the pip cache if we're told not to.
    cache_dir = _get_cache_dir(None, use_pip=False)
    assert cache_dir == Path.home() / ".pip-audit-cache"


def test_get_cache_dir_old_pip(monkeypatch):
    # Check the case where we have an old `pip`
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("1.0.0"))

    # When we supply a cache directory, always use that
    cache_dir = _get_cache_dir(Path("/tmp/foo/cache_dir"))
    assert str(cache_dir) == "/tmp/foo/cache_dir"

    # In this case, we can't query `pip` to figure out where its HTTP cache is
    # Instead, we use `~/.pip-audit-cache`
    cache_dir = _get_cache_dir(None)
    assert cache_dir == Path.home() / ".pip-audit-cache"


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
