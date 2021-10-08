import subprocess
from tempfile import TemporaryDirectory

import pytest
from packaging.version import Version

from pip_audit.virtual_env import VirtualEnv, VirtualEnvError


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


def test_virtual_env_malformed_freeze_output(monkeypatch):
    original_check_output = subprocess.check_output

    def check_output_mock(args, **kwargs):
        if "freeze" in args:
            return str.encode("Flask!=2.0.1")
        # If it's not a call to `pip freeze` just forward the args on
        return original_check_output(args, **kwargs)

    monkeypatch.setattr(subprocess, "check_output", check_output_mock)

    with TemporaryDirectory() as ve_dir:
        ve = VirtualEnv(["flask==2.0.1"])
        with pytest.raises(VirtualEnvError):
            ve.create(ve_dir)
