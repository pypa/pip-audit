import json

import pip_audit._format as format


def test_json(vuln_data):
    json_format = format.JsonFormat(True)
    expected_json = {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                        "description": "The first vulnerability",
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                        "description": "The second vulnerability",
                    },
                ],
            },
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [
                    {"id": "VULN-2", "fix_versions": [], "description": "The third vulnerability"}
                ],
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data, list()) == json.dumps(expected_json)


def test_json_no_desc(vuln_data):
    json_format = format.JsonFormat(False)
    expected_json = {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                    },
                    {
                        "id": "VULN-1",
                        "fix_versions": ["1.0"],
                    },
                ],
            },
            {
                "name": "bar",
                "version": "0.1",
                "vulns": [{"id": "VULN-2", "fix_versions": []}],
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data, list()) == json.dumps(expected_json)


def test_json_skipped_dep(vuln_data_skipped_dep):
    json_format = format.JsonFormat(False)
    expected_json = {
        "dependencies": [
            {
                "name": "foo",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "VULN-0",
                        "fix_versions": [
                            "1.1",
                            "1.4",
                        ],
                    },
                ],
            },
            {
                "name": "bar",
                "skip_reason": "skip-reason",
            },
        ],
        "fixes": [],
    }
    assert json_format.format(vuln_data_skipped_dep, list()) == json.dumps(expected_json)
