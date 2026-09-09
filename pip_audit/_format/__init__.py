"""
Output format interfaces and implementations for `pip-audit`.
"""

from typing import Any

from .columns import ColumnsFormat
from .interface import VulnerabilityFormat
from .json import JsonFormat
from .markdown import MarkdownFormat

__all__ = [
    "ColumnsFormat",
    "CycloneDxFormat",
    "VulnerabilityFormat",
    "JsonFormat",
    "MarkdownFormat",
]


def __getattr__(name: str) -> Any:
    # CycloneDX pulls in `cyclonedx-python-lib`, which is not available when
    # `pip-audit` is vendored into `pip`. Load it only if a caller asks for it.
    if name == "CycloneDxFormat":
        from .cyclonedx import CycloneDxFormat

        return CycloneDxFormat
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
