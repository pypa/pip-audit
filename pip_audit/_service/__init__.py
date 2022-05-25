"""
Vulnerability service interfaces and implementations for `pip-audit`.
"""

from .interface import (
    ConnectionError,
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
    "ConnectionError",
    "Dependency",
    "ResolvedDependency",
    "ServiceError",
    "SkippedDependency",
    "VulnerabilityResult",
    "VulnerabilityService",
    "OsvService",
    "PyPIService",
]
