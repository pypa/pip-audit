from pathlib import Path

import pretend  # type: ignore
from cachecontrol.caches import FileCache, SeparateBodyFileCache
from packaging.version import Version
from pip._internal.network.cache import SafeFileCache as _PipSafeFileCache
from platformdirs import user_cache_path

import pip_audit._cache as cache
from pip_audit._cache import (
    _get_cache_dir,
    _get_pip_cache,
    _LegacySafeFileCache,
    _SafeFileCache,
    caching_session,
)


def test_get_cache_dir(monkeypatch):
    # When we supply a cache directory, always use that. It isn't shared with a `pip`
    # cache, so it always uses the current (non-legacy) cache format.
    cache_dir = Path("/tmp/foo/cache_dir")
    assert _get_cache_dir(cache_dir) == (cache_dir, False)

    pip_cache_dir = Path("/fake/pip/cache/dir/http-v2")
    get_pip_cache = pretend.call_recorder(lambda: (pip_cache_dir, False))
    monkeypatch.setattr(cache, "_get_pip_cache", get_pip_cache)

    # When `pip cache dir` works, we use it. In this case, it's mocked.
    assert _get_cache_dir(None, use_pip=True) == (pip_cache_dir, False)


def test_get_pip_cache():
    # Actually running `pip cache dir` gets us a path within whichever cache format the
    # installed `pip` actually uses.
    cache_dir, is_legacy = _get_pip_cache()
    if cache._PIP_VERSION >= cache._MINIMUM_PIP_HTTP_V2_VERSION:
        assert cache_dir.name == "http-v2"
        assert is_legacy is False
    else:
        assert cache_dir.name == "http"
        assert is_legacy is True


def test_get_pip_cache_uses_http_v2_for_pip_23_3_and_newer(monkeypatch):
    # `pip` 23.3 (https://github.com/pypa/pip/pull/11143) introduced the `http-v2`
    # cache directory; every `pip` since should use it.
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("23.3"))
    cache_dir, is_legacy = _get_pip_cache()
    assert cache_dir.name == "http-v2"
    assert is_legacy is False


def test_get_pip_cache_uses_legacy_http_for_older_pip(monkeypatch):
    # `pip` versions older than 23.3 never write to `http-v2`, so we have to keep
    # reading/writing their legacy `http` cache to actually share a warm cache.
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("23.2"))
    cache_dir, is_legacy = _get_pip_cache()
    assert cache_dir.name == "http"
    assert is_legacy is True


def test_get_cache_dir_do_not_use_pip():
    expected = user_cache_path("pip-audit", appauthor=False)

    # Even with None, we never use the pip cache if we're told not to. This directory
    # isn't shared with any particular `pip` version, so it always uses the current
    # cache format.
    assert _get_cache_dir(None, use_pip=False) == (expected, False)


def test_get_cache_dir_pip_disabled_in_environment(monkeypatch):
    monkeypatch.setenv("PIP_NO_CACHE_DIR", "1")

    expected = user_cache_path("pip-audit", appauthor=False)

    # Even with use_pip=True, we avoid pip's cache if the environment tells us to.
    assert _get_cache_dir(None, use_pip=True) == (expected, False)


def test_get_cache_dir_old_pip(monkeypatch):
    # Check the case where we have an old `pip`
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("1.0.0"))

    # In this case, we can't query `pip` to figure out where its HTTP cache is
    # Instead, we use `~/.pip-audit-cache`
    cache_dir, is_legacy = _get_cache_dir(None)
    expected = user_cache_path("pip-audit", appauthor=False)
    assert cache_dir == expected
    assert is_legacy is False


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


def test_delete_legacy_cache_dir(monkeypatch, tmp_path):
    legacy = tmp_path / "pip-audit-cache"
    legacy.mkdir()
    assert legacy.exists()
    monkeypatch.setattr(cache, "_PIP_AUDIT_LEGACY_INTERNAL_CACHE", legacy)

    _get_cache_dir(None, use_pip=False)
    assert not legacy.exists()


def test_caching_session_selects_v2_cache_backend(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "_get_cache_dir", lambda *a, **kw: (tmp_path, False))
    session = caching_session(None)
    assert isinstance(session.adapters["https://"].cache, _SafeFileCache)


def test_caching_session_selects_legacy_cache_backend(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "_get_cache_dir", lambda *a, **kw: (tmp_path, True))
    session = caching_session(None)
    assert isinstance(session.adapters["https://"].cache, _LegacySafeFileCache)


class TestSafeFileCache:
    """Tests for `_SafeFileCache`, which mirrors `pip`'s current (`http-v2`) format."""

    def test_round_trip(self, tmp_path):
        c = _SafeFileCache(tmp_path)
        assert c.get("some-key") is None
        assert c.get_body("some-key") is None

        c.set("some-key", b"metadata")
        c.set_body("some-key", b"body")

        assert c.get("some-key") == b"metadata"
        body = c.get_body("some-key")
        assert body is not None
        assert body.read() == b"body"

    def test_entry_requires_both_metadata_and_body(self, tmp_path):
        # Mirrors `pip`'s own `SafeFileCache`: an entry is only valid once *both* its
        # metadata and its body have been written. A metadata-only file (e.g. a `set()`
        # whose matching `set_body()` hasn't landed yet, or a stale entry written by
        # `_LegacySafeFileCache`, which never writes a `.body` file) must read as a miss.
        c = _SafeFileCache(tmp_path)
        c.set("some-key", b"metadata")
        assert c.get("some-key") is None
        assert c.get_body("some-key") is None

    def test_delete(self, tmp_path):
        c = _SafeFileCache(tmp_path)
        c.set("some-key", b"metadata")
        c.set_body("some-key", b"body")

        c.delete("some-key")

        assert c.get("some-key") is None
        assert c.get_body("some-key") is None

        # Deleting a nonexistent key is a no-op, not an error.
        c.delete("some-other-key")

    def test_matches_cachecontrol_hashing(self, tmp_path):
        # The on-disk path for a given key must match `cachecontrol`'s own
        # `SeparateBodyFileCache`, since that's what `pip`'s `SafeFileCache` itself
        # uses to compute cache paths.
        ours = _SafeFileCache(tmp_path)
        theirs = SeparateBodyFileCache(str(tmp_path))

        assert ours._get_cache_path("some-key") == theirs._fn("some-key")

    def test_interop_with_real_pip_safe_file_cache(self, tmp_path):
        # `_SafeFileCache` is meant to be a "rough mirror" of `pip`'s actual
        # `SafeFileCache` (`pip._internal.network.cache.SafeFileCache`), close enough
        # that the two can share a single cache directory. We verify that directly
        # against the real, installed `pip`, rather than against our own understanding
        # of the format.
        ours = _SafeFileCache(tmp_path)
        theirs = _PipSafeFileCache(str(tmp_path))

        # A response `pip` wrote can be read back by us...
        theirs.set("shared-key", b"pip-metadata")
        theirs.set_body("shared-key", b"pip-body")
        assert ours.get("shared-key") == b"pip-metadata"
        body = ours.get_body("shared-key")
        assert body is not None
        assert body.read() == b"pip-body"

        # ...and a response we wrote can be read back by `pip`.
        ours.set("our-key", b"our-metadata")
        ours.set_body("our-key", b"our-body")
        assert theirs.get("our-key") == b"our-metadata"
        pip_body = theirs.get_body("our-key")
        assert pip_body is not None
        assert pip_body.read() == b"our-body"


class TestLegacySafeFileCache:
    """Tests for `_LegacySafeFileCache`, which mirrors `pip`'s pre-23.3 `http` format."""

    def test_round_trip(self, tmp_path):
        c = _LegacySafeFileCache(tmp_path)
        assert c.get("some-key") is None

        c.set("some-key", b"a serialized response")
        assert c.get("some-key") == b"a serialized response"

    def test_delete(self, tmp_path):
        c = _LegacySafeFileCache(tmp_path)
        c.set("some-key", b"a serialized response")

        c.delete("some-key")
        assert c.get("some-key") is None

    def test_interop_with_cachecontrol_file_cache(self, tmp_path):
        # `_LegacySafeFileCache` mirrors `pip`'s pre-23.3 `SafeFileCache`, which is
        # itself a copy of `cachecontrol`'s own combined-file `FileCache` format. We
        # verify interop against the real, installed `cachecontrol.caches.FileCache`,
        # rather than against our own understanding of the format.
        ours = _LegacySafeFileCache(tmp_path)
        theirs = FileCache(str(tmp_path))

        theirs.set("shared-key", b"a combined response")
        assert ours.get("shared-key") == b"a combined response"

        ours.set("our-key", b"our combined response")
        assert theirs.get("our-key") == b"our combined response"
