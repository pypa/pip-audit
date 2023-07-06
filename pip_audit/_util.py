"""
Utility functions for `pip-audit`.
"""

import sys
import tempfile
import os
from typing import NoReturn  # pragma: no cover

from packaging.version import Version


class CustomNamedTemporaryFile:
    """
    Workaround for NamedTemporaryFile which also works on Windows. This 
    version allows the created tempfile to be open and closed multiple times 
    without losing permissions on the file on Windows file systems.
    """
    def __init__(self, mode='w+b'):
        self._mode = mode

    def __enter__(self):
        # Generate a random temporary file
        file_name = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())
        # Ensure the file is created
        if not os.path.exists(file_name):
            open(file_name, 'x').close()
        # Open the file in the given mode
        self._tempFile = open(file_name, self._mode)
        return self._tempFile

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._tempFile.close()
        os.unlink(self._tempFile.name)

def assert_never(x: NoReturn) -> NoReturn:  # pragma: no cover
    """
    A hint to the typechecker that a branch can never occur.
    """
    assert False, f"unhandled type: {type(x).__name__}"


def python_version() -> Version:
    """
    Return a PEP-440-style version for the current Python interpreter.

    This is more rigorous than `platform.python_version`, which can include
    non-PEP-440-compatible data.
    """
    info = sys.version_info
    return Version(f"{info.major}.{info.minor}.{info.micro}")
