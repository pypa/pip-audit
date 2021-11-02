"""
Create virtual environments with a custom set of packages and inspect their dependencies.
"""

import json
import subprocess
import venv
from typing import Iterator, List, Optional, Tuple

from packaging.version import Version

from .state import AuditState


class VirtualEnv(venv.EnvBuilder):
    def __init__(self, install_args: List[str], state: Optional[AuditState] = None):
        super().__init__(with_pip=True)
        self._install_args = install_args
        self._packages: Optional[List[Tuple[str, Version]]] = None
        self._state = state

    # Override this hook with custom behaviour
    def post_setup(self, context):
        if self._state is not None:
            self._state.update_state(
                "Updating pip installation in isolated environment"
            )  # pragma: no cover

        # Firstly, upgrade our `pip` versions since `ensurepip` can leave us with an old version
        pip_upgrade_cmd = [context.env_exe, "-m", "pip", "install", "--upgrade", "pip"]
        try:
            subprocess.run(
                pip_upgrade_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as cpe:
            raise VirtualEnvError(f"Failed to upgrade `pip`: {pip_upgrade_cmd}") from cpe

        if self._state is not None:
            self._state.update_state(
                "Installing package in isolated environment"
            )  # pragma: no cover

        # Install our packages
        package_install_cmd = [context.env_exe, "-m", "pip", "install", *self._install_args]
        try:
            subprocess.run(
                package_install_cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as cpe:
            raise VirtualEnvError(f"Failed to install packages: {package_install_cmd}") from cpe

        if self._state is not None:
            self._state.update_state(
                "Processing package list from isolated environment"
            )  # pragma: no cover

        # Now parse the `pip list` output to figure out what packages our
        # environment contains
        list_cmd = [context.env_exe, "-m", "pip", "list", "-l", "--format", "json"]
        try:
            process = subprocess.run(
                list_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as cpe:
            raise VirtualEnvError(f"Failed to run `pip list`: {list_cmd}") from cpe
        list_output = process.stdout.decode("utf-8")
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

        yield from self._packages


class VirtualEnvError(Exception):
    pass
