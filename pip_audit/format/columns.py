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
        rows = []
        rows.append(["Package", "Version", "ID", "Description", "Affected Versions"])
        for dep, vulns in result.items():
            for vuln in vulns:
                rows.append(self._format_vuln(dep, vuln))
        vuln_strings, sizes = tabulate(rows)
        # Create and add a separator.
        if len(rows) > 0:
            vuln_strings.insert(1, " ".join(map(lambda x: "-" * x, sizes)))
        result_columns = str()
        for row in vuln_strings:
            if result_columns:
                result_columns += "\n"
            result_columns += row
        return result_columns

    def _format_vuln(self, dep: service.Dependency, vuln: service.VulnerabilityResult):
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
