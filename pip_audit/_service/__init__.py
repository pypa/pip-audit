"""
Vulnerability service interfaces and implementations for `pip-audit`.
"""

from .interface import (  # noqa: F401
    Dependency,
    ResolvedDependency,
    ServiceError,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from .osv import OsvService  # noqa: F401
from .pypi import PyPIService  # noqa: F401
