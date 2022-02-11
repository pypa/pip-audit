"""
`resolvelib` interactions for `pip-audit`.
"""

from .resolvelib import PYPI_URL, ResolveLibResolver, ResolveLibResolverError

__all__ = [
    "PYPI_URL",
    "ResolveLibResolver",
    "ResolveLibResolverError",
]
