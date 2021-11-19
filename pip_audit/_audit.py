"""
Core auditing APIs.
"""

import logging
from dataclasses import dataclass
from typing import Iterator, List, Tuple

from pip_audit._dependency_source import DependencySource
from pip_audit._service import Dependency, VulnerabilityResult, VulnerabilityService

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditOptions:
    """
    Settings the control the behavior of an `Auditor` instance.
    """

    dry_run: bool = False


class Auditor:
    """
    The core class of the `pip-audit` API.

    For a given dependency source and vulnerability service, supply a mapping of dependencies to
    known vulnerabilities.
    """

    def __init__(
        self,
        service: VulnerabilityService,
        options: AuditOptions = AuditOptions(),
    ):
        """
        Create a new auditor. Auditors start with no dependencies to audit;
        each `audit` step is fed a `DependencySource`.

        The behavior of the auditor can be optionally tweaked with the `options`
        parameter.
        """
        self._service = service
        self._options = options

    def audit(
        self, source: DependencySource
    ) -> Iterator[Tuple[Dependency, List[VulnerabilityResult]]]:
        """
        Perform the auditing step, collecting dependencies from `source`.
        """
        specs = source.collect()

        if self._options.dry_run:
            # Drain the iterator in dry-run mode.
            logger.info(f"Dry run: would have audited {len(list(specs))} packages")
            return {}
        else:
            yield from self._service.query_all(specs)
