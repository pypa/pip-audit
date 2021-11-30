"""
Functionality for formatting vulnerability results as a set of human-readable columns.
"""

from itertools import zip_longest
from typing import Any, Dict, Iterable, List, Tuple, cast

from packaging.version import Version

import pip_audit._service as service

from .interface import VulnerabilityFormat


def tabulate(rows: Iterable[Iterable[Any]]) -> Tuple[List[str], List[int]]:
    """Return a list of formatted rows and a list of column sizes.
    For example::
    >>> tabulate([['foobar', 2000], [0xdeadbeef]])
    (['foobar     2000', '3735928559'], [10, 4])
    """
    rows = [tuple(map(str, row)) for row in rows]
    sizes = [max(map(len, col)) for col in zip_longest(*rows, fillvalue="")]
    table = [" ".join(map(str.ljust, row, sizes)).rstrip() for row in rows]
    return table, sizes


class ColumnsFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results as a set of
    columns.
    """

    def __init__(self, output_desc: bool):
        """
        Create a new `ColumnFormat`.

        `output_desc` is a flag to determine whether descriptions for each vulnerability should be
        included in the output as they can be quite long and make the output difficult to read.
        """
        self.output_desc = output_desc

    def format(self, result: Dict[service.Dependency, List[service.VulnerabilityResult]]) -> str:
        """
        Returns a column formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        vuln_data: List[List[Any]] = []
        header = ["Name", "Version", "ID", "Fix Versions"]
        if self.output_desc:
            header.append("Description")
        vuln_data.append(header)
        for dep, vulns in result.items():
            if dep.is_skipped():
                continue
            dep = cast(service.ResolvedDependency, dep)
            for vuln in vulns:
                vuln_data.append(self._format_vuln(dep, vuln))

        vuln_strings, sizes = tabulate(vuln_data)

        # Create and add a separator.
        if len(vuln_data) > 0:
            vuln_strings.insert(1, " ".join(map(lambda x: "-" * x, sizes)))

        columns_string = str()
        for row in vuln_strings:
            if columns_string:
                columns_string += "\n"
            columns_string += row

        # Now display the skipped dependencies
        skip_data: List[List[Any]] = []
        skip_header = ["Name", "Skip Reason"]

        skip_data.append(skip_header)
        for dep, _ in result.items():
            if dep.is_skipped():
                dep = cast(service.SkippedDependency, dep)
                skip_data.append(self._format_skipped_dep(dep))

        # If we only have the header, that means that we haven't skipped any dependencies
        # In that case, don't bother printing the header
        if len(skip_data) <= 1:
            return columns_string

        skip_strings, sizes = tabulate(skip_data)

        # Create separator for skipped dependencies columns
        skip_strings.insert(1, " ".join(map(lambda x: "-" * x, sizes)))

        for row in skip_strings:
            columns_string += "\n" + row

        return columns_string

    def _format_vuln(
        self, dep: service.ResolvedDependency, vuln: service.VulnerabilityResult
    ) -> List[Any]:
        vuln_data = [
            dep.canonical_name,
            dep.version,
            vuln.id,
            self._format_fix_versions(vuln.fix_versions),
        ]
        if self.output_desc:
            vuln_data.append(vuln.description)
        return vuln_data

    def _format_fix_versions(self, fix_versions: List[Version]) -> str:
        return ",".join([str(version) for version in fix_versions])

    def _format_skipped_dep(self, dep: service.SkippedDependency) -> List[Any]:
        return [
            dep.canonical_name,
            dep.skip_reason,
        ]
