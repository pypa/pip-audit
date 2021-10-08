from pip_audit.virtual_env import VirtualEnvWrapper


def test_virtual_env():
    ve = VirtualEnvWrapper(["flask"])
    ve.create("test_env/")
    packages = list(ve.installed_packages)
    print(packages)
