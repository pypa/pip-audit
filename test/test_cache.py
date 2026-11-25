import gzip
import io
from email.utils import formatdate
from pathlib import Path

import pretend  # type: ignore
import pytest
from packaging.version import Version
from platformdirs import user_cache_path
from urllib3.response import HTTPResponse

import pip_audit._cache as cache
from pip_audit._cache import _get_cache_dir, _get_pip_cache, caching_session


def test_get_cache_dir(monkeypatch):
    # When we supply a cache directory, always use that
    cache_dir = Path("/tmp/foo/cache_dir")
    assert _get_cache_dir(cache_dir) == cache_dir

    cache_dir = Path("/fake/pip/cache/dir")
    get_pip_cache = pretend.call_recorder(lambda: cache_dir)
    monkeypatch.setattr(cache, "_get_pip_cache", get_pip_cache)

    # When `pip cache dir` works, we use it. In this case, it's mocked.
    assert _get_cache_dir(None, use_pip=True) == cache_dir


def test_get_pip_cache():
    # Actually running `pip cache dir` gets us some path that ends with "http"
    cache_dir = _get_pip_cache()
    assert cache_dir.stem == "http"


def test_get_cache_dir_do_not_use_pip():
    expected = user_cache_path("pip-audit", appauthor=False)

    # Even with None, we never use the pip cache if we're told not to.
    assert _get_cache_dir(None, use_pip=False) == expected


def test_get_cache_dir_pip_disabled_in_environment(monkeypatch):
    monkeypatch.setenv("PIP_NO_CACHE_DIR", "1")

    expected = user_cache_path("pip-audit", appauthor=False)

    # Even with use_pip=True, we avoid pip's cache if the environment tells us to.
    assert _get_cache_dir(None, use_pip=True) == expected


def test_get_cache_dir_old_pip(monkeypatch):
    # Check the case where we have an old `pip`
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("1.0.0"))

    # In this case, we can't query `pip` to figure out where its HTTP cache is
    # Instead, we use `~/.pip-audit-cache`
    cache_dir = _get_cache_dir(None)
    expected = user_cache_path("pip-audit", appauthor=False)
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


def test_delete_legacy_cache_dir(monkeypatch, tmp_path):
    legacy = tmp_path / "pip-audit-cache"
    legacy.mkdir()
    assert legacy.exists()
    monkeypatch.setattr(cache, "_PIP_AUDIT_LEGACY_INTERNAL_CACHE", legacy)

    _get_cache_dir(None, use_pip=False)
    assert not legacy.exists()


def test_caching_session(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "getproxies", lambda: {})
    session = caching_session(tmp_path)
    response = HTTPResponse(
        body=b'{"cached": true}',
        headers={"Date": formatdate(usegmt=True), "Cache-Control": "max-age=60"},
        status=200,
    )
    request = pretend.call_recorder(lambda *args, **kwargs: response)
    monkeypatch.setattr(session._pool, "request", request)

    assert session.request("GET", "https://example.test/data").json() == {"cached": True}
    assert session.request("GET", "https://example.test/data").json() == {"cached": True}
    assert len(request.calls) == 1


def test_caching_session_caches_decoded_response(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "getproxies", lambda: {})
    session = caching_session(tmp_path)
    body = gzip.compress(b'{"cached": true}')
    response = HTTPResponse(
        body=io.BytesIO(body),
        headers={
            "Content-Encoding": "gzip",
            "Content-Length": str(len(body)),
            "Date": formatdate(usegmt=True),
            "Cache-Control": "max-age=60",
        },
        status=200,
        preload_content=False,
        decode_content=True,
    )
    request = pretend.call_recorder(lambda *args, **kwargs: response)
    monkeypatch.setattr(session._pool, "request", request)

    assert session.request("GET", "https://example.test/data").json() == {"cached": True}
    assert session.request("GET", "https://example.test/data").json() == {"cached": True}
    assert len(request.calls) == 1


def test_caching_session_revalidates_decoded_response(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "getproxies", lambda: {})
    session = caching_session(tmp_path)
    body = gzip.compress(b'{"cached": true}')
    responses = [
        HTTPResponse(
            body=io.BytesIO(body),
            headers={
                "Content-Encoding": "gzip",
                "Content-Length": str(len(body)),
                "Date": formatdate(usegmt=True),
                "Cache-Control": "max-age=0",
                "ETag": "cached",
            },
            status=200,
            preload_content=False,
            decode_content=True,
        ),
        HTTPResponse(
            body=b"",
            headers={
                "Content-Encoding": "gzip",
                "Date": formatdate(usegmt=True),
                "Cache-Control": "max-age=60",
                "ETag": "cached",
            },
            status=304,
        ),
    ]
    request = pretend.call_recorder(lambda *args, **kwargs: responses.pop(0))
    monkeypatch.setattr(session._pool, "request", request)

    assert session.request("GET", "https://example.test/data").json() == {"cached": True}
    assert session.request("GET", "https://example.test/data").json() == {"cached": True}
    assert session.request("GET", "https://example.test/data").json() == {"cached": True}
    assert len(request.calls) == 2


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_caching_session_follows_redirect(monkeypatch, tmp_path, method):
    monkeypatch.setattr(cache, "getproxies", lambda: {})
    session = caching_session(tmp_path)
    requests = []

    def request(method, url, **kwargs):
        requests.append((method, url, kwargs))
        if url.endswith("/source"):
            return HTTPResponse(
                body=b"",
                headers={"Location": "/target"},
                status=302,
            )
        return HTTPResponse(body=b'{"redirected": true}', status=200)

    monkeypatch.setattr(session._pool, "request", request)

    response = session.request(
        method,
        "https://example.test/source",
        headers={"Content-Type": "application/json"},
        body=b"{}",
    )

    assert response.json() == {"redirected": True}
    assert [(method, url) for method, url, _ in requests] == [
        (method, "https://example.test/source"),
        ("GET", "https://example.test/target"),
    ]
    assert "body" not in requests[1][2]
    assert "Content-Type" not in requests[1][2]["headers"]


def test_caching_session_preserves_authorization_on_equivalent_origin(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "getproxies", lambda: {})
    session = caching_session(tmp_path)
    requests = []

    def request(method, url, **kwargs):
        requests.append((method, url, kwargs))
        if url.endswith("/source"):
            return HTTPResponse(
                body=b"",
                headers={"Location": "https://example.test:443/target"},
                status=307,
            )
        return HTTPResponse(body=b"{}", status=200)

    monkeypatch.setattr(session._pool, "request", request)

    session.request(
        "GET",
        "https://example.test/source",
        headers={"Authorization": "******"},
    )

    assert requests[1][2]["headers"]["Authorization"] == "******"


def test_caching_session_caches_redirects(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "getproxies", lambda: {})
    session = caching_session(tmp_path)
    requests = []

    def request(method, url, **kwargs):
        requests.append((method, url))
        if url.endswith("/source"):
            return HTTPResponse(
                body=b"",
                headers={"Location": "/target", "Date": formatdate(usegmt=True)},
                status=308,
            )
        return HTTPResponse(
            body=b'{"redirected": true}',
            headers={"Date": formatdate(usegmt=True), "Cache-Control": "max-age=60"},
            status=200,
        )

    monkeypatch.setattr(session._pool, "request", request)

    assert session.request("GET", "https://example.test/source").json() == {"redirected": True}
    assert session.request("GET", "https://example.test/source").json() == {"redirected": True}
    assert requests == [
        ("GET", "https://example.test/source"),
        ("GET", "https://example.test/target"),
    ]


def test_caching_session_uses_environment_proxy(monkeypatch, tmp_path):
    credentials = "proxy-user:proxy-password"
    monkeypatch.setattr(
        cache,
        "getproxies",
        lambda: {"https": f"https://{credentials}@proxy.example.test"},
    )
    monkeypatch.setattr(cache, "proxy_bypass", lambda host: False)
    response = HTTPResponse(body=b"{}", status=200)
    request = pretend.call_recorder(lambda *args, **kwargs: response)
    proxy_manager = pretend.stub(request=request)
    proxy_manager_factory = pretend.call_recorder(lambda *args, **kwargs: proxy_manager)
    monkeypatch.setattr(cache.urllib3, "ProxyManager", proxy_manager_factory)
    session = caching_session(tmp_path)

    assert session.request("GET", "https://example.test/data") is response
    assert len(proxy_manager_factory.calls) == 1
    assert len(request.calls) == 1
    assert (
        proxy_manager_factory.calls[0]
        .kwargs["proxy_headers"]["proxy-authorization"]
        .startswith("Basic ")
    )


def test_caching_session_respects_port_specific_proxy_bypass(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cache,
        "getproxies",
        lambda: {"https": "https://proxy.example.test"},
    )
    monkeypatch.setattr(cache, "proxy_bypass", lambda host: host == "example.test:8443")
    session = caching_session(tmp_path)
    response = HTTPResponse(body=b"{}", status=200)
    request = pretend.call_recorder(lambda *args, **kwargs: response)
    monkeypatch.setattr(session._pool, "request", request)

    assert session.request("GET", "https://example.test:8443/data") is response
    assert len(request.calls) == 1


def test_caching_session_normalizes_schemeless_proxy(monkeypatch, tmp_path):
    monkeypatch.setattr(cache, "getproxies", lambda: {"https": "proxy.example.test:8080"})
    monkeypatch.setattr(cache, "proxy_bypass", lambda host: False)
    response = HTTPResponse(body=b"{}", status=200)
    request = pretend.call_recorder(lambda *args, **kwargs: response)
    proxy_manager = pretend.stub(request=request)
    proxy_manager_factory = pretend.call_recorder(lambda *args, **kwargs: proxy_manager)
    monkeypatch.setattr(cache.urllib3, "ProxyManager", proxy_manager_factory)
    session = caching_session(tmp_path)

    session.request("GET", "https://example.test/data")
    assert proxy_manager_factory.calls[0].args[0] == "http://proxy.example.test:8080"


def test_caching_session_uses_ca_bundle(monkeypatch, tmp_path):
    ca_bundle = tmp_path / "ca.pem"
    ca_bundle.write_text("certificate")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(ca_bundle))
    pool_manager = pretend.call_recorder(lambda *args, **kwargs: pretend.stub())
    monkeypatch.setattr(cache.urllib3, "PoolManager", pool_manager)

    caching_session(tmp_path)

    assert pool_manager.calls[0].kwargs["ca_certs"] == str(ca_bundle)
