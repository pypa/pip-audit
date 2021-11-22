import subprocess
from tempfile import TemporaryDirectory

import pytest
from packaging.version import Version

from pip_audit._virtual_env import VirtualEnv, VirtualEnvError


def test_virtual_env():
    with TemporaryDirectory() as ve_dir:
        ve = VirtualEnv(["flask==2.0.1"])
        ve.create(ve_dir)
        packages = list(ve.installed_packages)
    assert ("Flask", Version("2.0.1")) in packages


def test_virtual_env_incorrect_usage():
    ve = VirtualEnv(["flask==2.0.1"])

    with pytest.raises(VirtualEnvError):
        list(ve.installed_packages)


def test_virtual_env_failed_package_installation(monkeypatch):
    original_run = subprocess.run

    def run_mock(args, **kwargs):
        if "flask==2.0.1" in args:
            raise subprocess.CalledProcessError(-1, str())
        # If it's not the package installation command, then call the original run
        return original_run(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", run_mock)

    with TemporaryDirectory() as ve_dir:
        ve = VirtualEnv(["flask==2.0.1"])
        with pytest.raises(VirtualEnvError):
            ve.create(ve_dir)


def test_virtual_env_failed_pip_upgrade(monkeypatch):
    original_run = subprocess.run

    def run_mock(args, **kwargs):
        # We have to be a bit more specific than usual here because the `EnvBuilder` invokes
        # `ensurepip` with similar looking arguments and we DON'T want to mock that call.
        if set(["install", "--upgrade", "pip"]).issubset(set(args)):
            raise subprocess.CalledProcessError(-1, str())
        # If it's not a call to upgrade pip, then call the original run
        return original_run(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", run_mock)

    with TemporaryDirectory() as ve_dir:
        ve = VirtualEnv(["flask==2.0.1"])
        with pytest.raises(VirtualEnvError):
            ve.create(ve_dir)


def test_virtual_env_failed_pip_list(monkeypatch):
    original_run = subprocess.run

    def run_mock(args, **kwargs):
        if "json" in args:
            raise subprocess.CalledProcessError(-1, str())
        # If it's not a call to `pip list`, then call the original run
        return original_run(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", run_mock)

    with TemporaryDirectory() as ve_dir:
        ve = VirtualEnv(["flask==2.0.1"])
        with pytest.raises(VirtualEnvError):
            ve.create(ve_dir)
