"""
Dependency source interfaces and implementations for `pip-audit`.
"""

from .interface import (
    PYPI_URL,
    DependencyFixError,
    DependencySource,
    DependencySourceError,
    HashMismatchError,
    HashMissingError,
    InvalidRequirementSpecifier,
    RequirementHashes,
    UnsupportedHashAlgorithm,
)
from .pip import PipSource, PipSourceError
from .pyproject import PyProjectSource
from .requirement import RequirementSource

__all__ = [
    "PYPI_URL",
    "DependencyFixError",
    "DependencySource",
    "DependencySourceError",
    "HashMismatchError",
    "HashMissingError",
    "InvalidRequirementSpecifier",
    "PipSource",
    "PipSourceError",
    "PyProjectSource",
    "RequirementHashes",
    "RequirementSource",
    "UnsupportedHashAlgorithm",
]
