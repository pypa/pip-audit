from itertools import zip_longest
from typing import Any, Dict, Iterable, List, Tuple

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
    def format(self, result: Dict[service.Dependency, List[service.VulnerabilityResult]]) -> str:
        vuln_data: List[List[Any]] = []
        vuln_data.append(["Package", "Version", "ID", "Description", "Affected Versions"])
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
        return [
            dep.package,
            dep.version,
            vuln.id,
            vuln.description,
            self._format_version_range(vuln.version_range),
        ]

    def _format_version_range(self, version_range: List[service.VersionRange]) -> str:
        range_string = str()
        for v in version_range:
            if range_string:
                range_string += ", "
            introduced = v.introduced if v.introduced is not None else "N/A"
            fixed = v.fixed if v.fixed is not None else "N/A"
            range_string += f"({introduced} => fix: {fixed})"
        return range_string
