"""
Core auditing APIs.
"""

from dataclasses import dataclass

from pip_audit.service import VulnerabilityService


@dataclass(frozen=True)
class AuditOptions:
    """
    Settings the control the behavior of an `Auditor` instance.
    """

    dry_run: bool


class Auditor:
    def __init__(self, service: VulnerabilityService, options: AuditOptions):
        self._service = service
        self._options = options
