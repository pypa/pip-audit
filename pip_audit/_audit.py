"""
Core auditing APIs.
"""

import logging
from dataclasses import dataclass
from typing import Iterator, List, Set, Tuple

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

        Individual vulnerability results are uniqued based on their `aliases` sets:
        any two results for the same dependency that share an alias are collapsed
        into a single result with a union of all aliases.

        `PYSEC`-identified results are given priority over other results.
        """
        specs = source.collect()

        if self._options.dry_run:
            # Drain the iterator in dry-run mode.
            logger.info(f"Dry run: would have audited {len(list(specs))} packages")
            return {}
        else:
            for dep, vulns in self._service.query_all(specs):
                unique_vulns: List[VulnerabilityResult] = []
                seen_aliases: Set[str] = set()

                # First pass, add all PYSEC vulnerabilities and track their
                # alias sets.
                for v in vulns:
                    if not v.id.startswith("PYSEC"):
                        continue

                    seen_aliases.update(v.aliases | {v.id})
                    unique_vulns.append(v)

                # Second pass: add any non-PYSEC vulnerabilities.
                for v in vulns:
                    # If we've already seen this vulnerability by another name,
                    # don't add it. Instead, find the previous result and update
                    # its alias set.
                    if seen_aliases.intersection(v.aliases | {v.id}):
                        idx, previous = next(
                            (i, p) for (i, p) in enumerate(unique_vulns) if p.alias_of(v)
                        )
                        unique_vulns[idx] = previous.merge_aliases(v)
                        continue

                    seen_aliases.update(v.aliases | {v.id})
                    unique_vulns.append(v)

                yield (dep, unique_vulns)
