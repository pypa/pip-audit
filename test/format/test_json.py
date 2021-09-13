import json

import pip_audit.format as format

from .vuln_data import TEST_VULN_DATA


def test_json():
    json_format = format.JsonFormat()
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
                        {"fixed": "1.4"},
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
    assert json_format.format(TEST_VULN_DATA) == json.dumps(expected_json)
