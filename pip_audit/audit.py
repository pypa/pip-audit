"""
Core auditing APIs.
"""

from dataclasses import dataclass

from pip_audit.dependency_source import DependencySource
from pip_audit.service import VulnerabilityService


@dataclass(frozen=True)
class AuditOptions:
    """
    Settings the control the behavior of an `Auditor` instance.
    """

    dry_run: bool


class Auditor:
    def __init__(
        self, source: DependencySource, service: VulnerabilityService, options: AuditOptions
    ):
        self._source = source
        self._service = service
        self._options = options

    def audit(self):
        raise NotImplementedError
