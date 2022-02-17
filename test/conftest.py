import tempfile
from pathlib import Path

import pytest
from packaging.version import Version

from pip_audit._dependency_source.interface import DependencySource
from pip_audit._service.interface import (
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)


def pytest_addoption(parser):
    parser.addoption(
        "--skip-online", action="store_true", help="skip tests that require network connectivity"
    )


def pytest_runtest_setup(item):
    if "online" in item.keywords and item.config.getoption("--skip-online"):
        pytest.skip("skipping test that requires network connectivity due to `--skip-online` flag")


def pytest_configure(config):
    config.addinivalue_line("markers", "online: mark test as requiring network connectivity")


@pytest.fixture(autouse=True)
def spec():
    def _spec(version):
        return ResolvedDependency(name="foo", version=Version(version))

    return _spec


@pytest.fixture(autouse=True)
def vuln_service():
    # A dummy service that only returns results for the "foo" package
    # between [1.0.0, 1.1.0).
    class Service(VulnerabilityService):
        def query(self, spec):
            introduced = Version("1.0.0")
            fixed = Version("1.1.0")

            if spec.name == "foo" and (introduced <= spec.version < fixed):
                return spec, [
                    VulnerabilityResult(
                        id="fake-id",
                        description="this is not a real result",
                        fix_versions=[fixed],
                        aliases=set(),
                    )
                ]

            return spec, []

    return Service


@pytest.fixture(autouse=True)
def dep_source(spec):
    class Source(DependencySource):
        def collect(self):
            yield spec("1.0.1")

        def fix(self, _) -> None:
            raise NotImplementedError

    return Source


@pytest.fixture(scope="session")
def cache_dir():
    cache = tempfile.TemporaryDirectory()
    yield cache.name
    cache.cleanup()


@pytest.fixture
def req_file():
    def _req_file():
        req_file = tempfile.NamedTemporaryFile()
        req_file.close()

        req_path = Path(req_file.name)
        assert not req_path.exists()
        return req_path

    return _req_file
