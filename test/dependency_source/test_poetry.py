from __future__ import annotations

from pathlib import Path

from packaging.version import Version

from pip_audit._dependency_source import PoetrySource
from pip_audit._service import ResolvedDependency, SkippedDependency

TEST_DATA_PATH = Path(__file__).parent / "data"


def test_collect(tmp_path: Path) -> None:
    lock_content = (TEST_DATA_PATH / "poetry.lock").read_text()
    lock_path = tmp_path / "poetry.lock"
    lock_path.write_text(lock_content)
    sourcer = PoetrySource(path=lock_path)
    actual = list(sourcer.collect())
    expected = [
        ResolvedDependency(name="jinja2", version=Version("2.11.3")),
        ResolvedDependency(name="markupsafe", version=Version("2.1.1")),
    ]
    assert actual == expected


def test_invalid_version(tmp_path: Path) -> None:
    lock_content = (TEST_DATA_PATH / "poetry.lock").read_text()
    lock_content = lock_content.replace("2.11.3", "oh-hi-mark")
    lock_path = tmp_path / "poetry.lock"
    lock_path.write_text(lock_content)
    sourcer = PoetrySource(path=lock_path)
    deps = list(sourcer.collect())
    assert [dep.name for dep in deps] == ["jinja2", "markupsafe"]
    assert isinstance(deps[0], SkippedDependency)
