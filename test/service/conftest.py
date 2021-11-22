import tempfile

import pytest


@pytest.fixture(scope="session")
def cache_dir():
    cache = tempfile.TemporaryDirectory()
    yield cache.name
    cache.cleanup()
