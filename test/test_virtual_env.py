from tempfile import TemporaryDirectory

from packaging.version import Version

from pip_audit.virtual_env import VirtualEnv


def test_virtual_env():
    with TemporaryDirectory() as ve_dir:
        ve = VirtualEnv(["flask==2.0.1"])
        ve.create(ve_dir)
        packages = list(ve.installed_packages)
    assert ("Flask", Version("2.0.1")) in packages
