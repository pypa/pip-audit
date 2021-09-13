from typing import Dict, List

from packaging.version import Version

import pip_audit.format as format
import pip_audit.service as service


def test_columns():
    columns_format = format.ColumnsFormat()
    result: Dict[service.Dependency, List[service.VulnerabilityResult]] = {
        service.Dependency(package="foo", version="1.0"): [
            service.VulnerabilityResult(
                id="VULN-0",
                description="The first vulnerability",
                version_range=[
                    service.VersionRange(introduced=Version("0.9"), fixed=Version("1.1")),
                    service.VersionRange(introduced=Version("1.3"), fixed=Version("1.4")),
                ],
            ),
            service.VulnerabilityResult(
                id="VULN-1",
                description="The second vulnerability",
                version_range=[
                    service.VersionRange(introduced=Version("0.5"), fixed=Version("1.0"))
                ],
            ),
        ],
        service.Dependency(package="bar", version="0.1"): [
            service.VulnerabilityResult(
                id="VULN-2",
                description="The third vulnerability",
                version_range=[service.VersionRange(introduced=Version("0.1"), fixed=None)],
            )
        ],
    }
    expected_columns = """Package Version ID     Description              Affected Versions
------- ------- ------ ------------------------ ------------------------------------
foo     1.0     VULN-0 The first vulnerability  (0.9 => fix: 1.1), (1.3 => fix: 1.4)
foo     1.0     VULN-1 The second vulnerability (0.5 => fix: 1.0)
bar     0.1     VULN-2 The third vulnerability  (0.1 => fix: N/A)"""
    assert columns_format.format(result) == expected_columns
