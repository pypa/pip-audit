import json
from typing import Dict, List

from packaging.version import Version

import pip_audit.format as format
import pip_audit.service as service


def test_json():
    json_format = format.JsonFormat()
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
    expected_json = [
        {
            "package": "foo",
            "version": "1.0",
            "vulns": [
                {
                    "id": "VULN-0",
                    "description": "The first vulnerability",
                    "version_range": [
                        {"introduced": "0.9", "fixed": "1.1"},
                        {"introduced": "1.3", "fixed": "1.4"},
                    ],
                },
                {
                    "id": "VULN-1",
                    "description": "The second vulnerability",
                    "version_range": [
                        {"introduced": "0.5", "fixed": "1.0"},
                    ],
                },
            ],
        },
        {
            "package": "bar",
            "version": "0.1",
            "vulns": [
                {
                    "id": "VULN-2",
                    "description": "The third vulnerability",
                    "version_range": [{"introduced": "0.1"}],
                }
            ],
        },
    ]
    assert json_format.format(result) == json.dumps(expected_json)
