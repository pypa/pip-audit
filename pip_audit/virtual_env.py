"""
Create virtual environments with a custom set of packages and inspect their dependencies.
"""

import subprocess
import venv
from os import linesep
from typing import Iterator, List, Optional, Tuple

from packaging.version import Version


class VirtualEnv(venv.EnvBuilder):
    def __init__(self, install_cmds: List[str]):
        super().__init__(with_pip=True)
        self.install_cmds = install_cmds
        self.packages: Optional[List[Tuple[str, Version]]] = None

    # Override this hook with custom behaviour
    def post_setup(self, context):
        # Install our packages
        for install_cmd in self.install_cmds:
            cmd = [context.env_exe, "-m", "pip", "install"]
            cmd.extend(install_cmd.split())
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)

        # Now parse the `pip list` output to figure out what packages our
        # environment contains
        list_cmd = [context.env_exe, "-m", "pip", "freeze", "-l"]
        list_output = subprocess.check_output(list_cmd).decode("utf-8")

        # Convert into a series of name, version pairs
        self.packages = []
        lines = list_output.split(linesep)
        for line in lines:
            # Skip source distributions and comments
            if not line or line.startswith("#") or line.startswith("-e"):
                continue
            parts = line.split("==")
            if len(parts) != 2:
                raise VirtualEnvError(f"Malformed line in `pip freeze` output: {line}")
            self.packages.append((parts[0], Version(parts[1])))

    @property
    def installed_packages(self) -> Iterator[Tuple[str, Version]]:
        if self.packages is None:
            raise VirtualEnvError(
                "Invalid usage of wrapper."
                "The `create` method must be called before inspecting `installed_packages`."
            )
        for name, version in self.packages:
            yield (name, version)


class VirtualEnvError(Exception):
    pass
