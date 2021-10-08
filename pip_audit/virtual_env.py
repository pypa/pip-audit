"""
Create virtual environments with a custom set of packages and inspect their dependencies.
"""

import json
import subprocess
import venv
from typing import Iterator, List, Optional, Tuple

from packaging.version import Version


class VirtualEnv(venv.EnvBuilder):
    def __init__(self, install_cmds: List[str]):
        super().__init__(with_pip=True)
        self._install_cmds = install_cmds
        self._packages: Optional[List[Tuple[str, Version]]] = None

    # Override this hook with custom behaviour
    def post_setup(self, context):
        # Install our packages
        for install_cmd in self._install_cmds:
            cmd = [context.env_exe, "-m", "pip", "install"]
            cmd.extend(install_cmd.split())
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)

        # Now parse the `pip list` output to figure out what packages our
        # environment contains
        list_cmd = [context.env_exe, "-m", "pip", "list", "-l", "--format", "json"]
        list_output = subprocess.check_output(list_cmd).decode("utf-8")
        package_list = json.loads(list_output)

        # Convert into a series of name, version pairs
        self._packages = []
        for package in package_list:
            self._packages.append((package["name"], Version(package["version"])))

    @property
    def installed_packages(self) -> Iterator[Tuple[str, Version]]:
        if self._packages is None:
            raise VirtualEnvError(
                "Invalid usage of wrapper."
                "The `create` method must be called before inspecting `installed_packages`."
            )
        for package in self._packages:
            yield package


class VirtualEnvError(Exception):
    pass
