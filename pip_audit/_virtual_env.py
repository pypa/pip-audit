"""
Create virtual environments with a custom set of packages and inspect their dependencies.
"""

from __future__ import annotations

import json
import logging
import venv
from types import SimpleNamespace
from typing import Iterator

from packaging.version import Version

from ._state import AuditState
from ._subprocess import CalledProcessError, run

logger = logging.getLogger(__name__)


class VirtualEnv(venv.EnvBuilder):
    """
    A wrapper around `EnvBuilder` that allows a custom package to be installed, and its resulting
    dependencies inspected.

    The `pip-audit` API uses this functionality internally to deduce what the dependencies are for a
    given source distribution since this can't be determined statically.

    The `create` method MUST be called before inspecting the `installed_packages` property otherwise
    a `VirtualEnvError` will be raised.

    The expected usage is:
    ```
    # Create a virtual environment and install the `pip-api` package.
    ve = VirtualEnv(["pip-api"])
    ve.create(".venv/")
    for (name, version) in ve.installed_packages:
        print(f"Installed package {name} ({version})")
    ```
    """

    def __init__(self, install_args: list[str], state: AuditState = AuditState()):
        """
        Create a new `VirtualEnv`.

        `install_args` is the list of arguments that would be used the custom install command. For
        example, if you wanted to execute `pip install -e /tmp/my_pkg`, you would create the
        `VirtualEnv` like so:
        ```
        ve = VirtualEnv(["-e", "/tmp/my_pkg"])
        ```

        `state` is an `AuditState` to use for state callbacks.
        """
        super().__init__(with_pip=True)
        self._install_args = install_args
        self._packages: list[tuple[str, Version]] | None = None
        self._state = state

    def post_setup(self, context: SimpleNamespace) -> None:
        """
        Install the custom package and populate the list of installed packages.

        This method is overridden from `EnvBuilder` to execute immediately after the virtual
        environment has been created and should not be called directly.

        We do a few things in our custom post-setup:
        - Upgrade the `pip` version. We'll be using `pip list` with the `--format json` option which
          requires a non-ancient version for `pip`.
        - Install `wheel`. When our packages install their own dependencies, they might be able
          to do so through wheels, which are much faster and don't require us to run
          setup scripts.
        - Execute the custom install command.
        - Call `pip list`, and parse the output into a list of packages to be returned from when the
          `installed_packages` property is queried.
        """
        self._state.update_state("Updating pip installation in isolated environment")

        # Firstly, upgrade our `pip` versions since `ensurepip` can leave us with an old version
        # and install `wheel` in case our package dependencies are offered as wheels
        # TODO: This is probably replaceable with the `upgrade_deps` option on `EnvBuilder`
        # itself, starting with Python 3.9.
        pip_upgrade_cmd = [
            context.env_exe,
            "-m",
            "pip",
            "install",
            "--upgrade",
            "pip",
            "wheel",
            "setuptools",
        ]
        try:
            run(pip_upgrade_cmd, state=self._state)
        except CalledProcessError as cpe:
            raise VirtualEnvError(f"Failed to upgrade `pip`: {pip_upgrade_cmd}") from cpe

        self._state.update_state("Installing package in isolated environment")

        # Install our packages
        package_install_cmd = [
            context.env_exe,
            "-m",
            "pip",
            "install",
            *self._install_args,
        ]
        try:
            run(package_install_cmd, state=self._state)
        except CalledProcessError as cpe:
            raise VirtualEnvError(f"Failed to install packages: {package_install_cmd}") from cpe

        self._state.update_state("Processing package list from isolated environment")

        # Now parse the `pip list` output to figure out what packages our
        # environment contains
        list_cmd = [context.env_exe, "-m", "pip", "list", "-l", "--format", "json"]
        try:
            stdout = run(list_cmd, state=self._state)
        except CalledProcessError as cpe:
            raise VirtualEnvError(f"Failed to run `pip list`: {list_cmd}") from cpe
        package_list = json.loads(stdout)

        # Convert into a series of name, version pairs
        self._packages = []
        for package in package_list:
            self._packages.append((package["name"], Version(package["version"])))

    @property
    def installed_packages(self) -> Iterator[tuple[str, Version]]:
        """
        A property to inspect the list of packages installed in the virtual environment.

        This method can only be called after the `create` method has been called.
        """
        if self._packages is None:
            raise VirtualEnvError(
                "Invalid usage of wrapper."
                "The `create` method must be called before inspecting `installed_packages`."
            )

        yield from self._packages


class VirtualEnvError(Exception):
    """
    Raised when `VirtualEnv` fails to build or inspect dependencies, for any reason.
    """

    pass
