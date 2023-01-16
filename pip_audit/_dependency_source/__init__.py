"""
Dependency source interfaces and implementations for `pip-audit`.
"""

from .interface import (
    DependencyFixError,
    DependencyResolver,
    DependencyResolverError,
    DependencySource,
    DependencySourceError,
    HashMismatchError,
    HashMissingError,
    RequirementHashes,
    UnsupportedHashAlgorithm,
)
from .pip import PipSource, PipSourceError
from .pyproject import PyProjectSource
from .requirement import RequirementSource
from .resolvelib import PYPI_URL, ResolveLibResolver

__all__ = [
    "PYPI_URL",
    "DependencyFixError",
    "DependencyResolver",
    "DependencyResolverError",
    "DependencySource",
    "DependencySourceError",
    "HashMismatchError",
    "HashMissingError",
    "PipSource",
    "PipSourceError",
    "PyProjectSource",
    "RequirementHashes",
    "RequirementSource",
    "ResolveLibResolver",
    "UnsupportedHashAlgorithm",
]
