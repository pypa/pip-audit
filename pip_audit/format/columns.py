"""
Functionality for formatting vulnerability results as a set of human-readable columns.
"""

from itertools import zip_longest
from typing import Any, Dict, Iterable, List, Tuple

from packaging.version import Version

import pip_audit.service as service

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

        return columns_string

    def _format_vuln(self, dep: service.Dependency, vuln: service.VulnerabilityResult) -> List[Any]:
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
