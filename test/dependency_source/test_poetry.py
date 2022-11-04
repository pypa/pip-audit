from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from textwrap import dedent
from typing import Callable

import pytest
from packaging.version import Version

from pip_audit._dependency_source import PoetrySource
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import ResolvedDependency


@pytest.fixture
def lock(tmp_path: Path) -> Callable:
    def callback(*deps: str) -> Path:
        metadata = """
            [tool.poetry]
            name = "poetry-demo"
            version = "0.1.0"
            description = ""
            authors = ["someone <mail@example.com>"]

            [tool.poetry.dependencies]
            python = "^3.7"
        """
        metadata = dedent(metadata)
        metadata += "\n".join(deps)
        (tmp_path / "pyproject.toml").write_text(metadata)
        cmd = [sys.executable, "-m", "poetry", "lock", "--no-update"]
        subprocess.run(cmd, cwd=tmp_path).check_returncode()
        lock_path = tmp_path / "poetry.lock"
        assert lock_path.exists()
        return lock_path

    return callback


def test_collect_and_fix(lock: Callable) -> None:
    lock_path: Path = lock("Jinja2 = '2.7.1'")
    sourcer = PoetrySource(path=lock_path)

    # collect
    deps = list(sourcer.collect())
    assert [dep.name for dep in deps] == ["jinja2", "markupsafe"]
    assert isinstance(deps[0], ResolvedDependency)
    assert isinstance(deps[1], ResolvedDependency)
    assert str(deps[0].version) == "2.7.1"

    # unlock the version in metadata
    meta_path = lock_path.parent / "pyproject.toml"
    meta_content = meta_path.read_text()
    meta_content = meta_content.replace("2.7.1", "2.7.*")
    meta_path.write_text(meta_content)

    # fix
    sourcer.fix(ResolvedFixVersion(dep=deps[0], version=Version("2.7.3")))
    content = lock_path.read_text()
    assert 'version = "2.7.3"' in content
    assert "2.7.1" not in content
