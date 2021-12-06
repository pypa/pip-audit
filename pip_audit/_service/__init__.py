"""
Vulnerability service interfaces and implementations for `pip-audit`.
"""

from .interface import (
    Dependency,
    ResolvedDependency,
    ServiceError,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from .osv import OsvService
from .pypi import PyPIService

__all__ = [
    "Dependency",
    "ResolvedDependency",
    "ServiceError",
    "SkippedDependency",
    "VulnerabilityResult",
    "VulnerabilityService",
    "OsvService",
    "PyPIService",
]
