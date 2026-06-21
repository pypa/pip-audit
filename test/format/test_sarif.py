import json

import pip_audit._format as format


def test_sarif(vuln_data):
    sarif_format = format.SarifFormat(output_desc=True)
    expected_json = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "informationUri": "https://pypi.org/project/pip-audit/",
                        "rules": [
                            {
                                "id": "VULN-0",
                                "shortDescription": {
                                    "text": "The first vulnerability"
                                },
                                "helpUri": "https://osv.dev/vulnerability/VULN-0",
                                "fullDescription": {
                                    "text": "The first vulnerability"
                                }
                            },
                            {
                                "id": "VULN-1",
                                "shortDescription": {
                                    "text": "The second vulnerability"
                                },
                                "helpUri": "https://osv.dev/vulnerability/VULN-1",
                                "fullDescription": {
                                    "text": "The second vulnerability"
                                }
                            },
                            {
                                "id": "VULN-2",
                                "shortDescription": {
                                    "text": "The third vulnerability"
                                },
                                "helpUri": "https://osv.dev/vulnerability/VULN-2",
                                "fullDescription": {
                                    "text": "The third vulnerability"
                                }
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "VULN-0",
                        "level": "error",
                        "message": {
                            "text": "`foo` has a known vulnerability: VULN-0\nThe first vulnerability"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "pip-audit"
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "VULN-1",
                        "level": "error",
                        "message": {
                            "text": "`foo` has a known vulnerability: VULN-1\nThe second vulnerability"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "pip-audit"
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "VULN-2",
                        "level": "error",
                        "message": {
                            "text": "`bar` has a known vulnerability: VULN-2\nThe third vulnerability"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "pip-audit"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    
    assert expected_json == json.loads(sarif_format.format(vuln_data, list()))


def test_sarif_no_desc(vuln_data):
    sarif_format = format.SarifFormat(output_desc=False)
    expected_json = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "informationUri": "https://pypi.org/project/pip-audit/",
                        "rules": [
                            {
                                "id": "VULN-0",
                                "shortDescription": {
                                    "text": "VULN-0"
                                },
                                "helpUri": "https://osv.dev/vulnerability/VULN-0"
                            },
                            {
                                "id": "VULN-1",
                                "shortDescription": {
                                    "text": "VULN-1"
                                },
                                "helpUri": "https://osv.dev/vulnerability/VULN-1"
                            },
                            {
                                "id": "VULN-2",
                                "shortDescription": {
                                    "text": "VULN-2"
                                },
                                "helpUri": "https://osv.dev/vulnerability/VULN-2"
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "VULN-0",
                        "level": "error",
                        "message": {
                            "text": "`foo` has a known vulnerability: VULN-0"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "pip-audit"
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "VULN-1",
                        "level": "error",
                        "message": {
                            "text": "`foo` has a known vulnerability: VULN-1"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "pip-audit"
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "VULN-2",
                        "level": "error",
                        "message": {
                            "text": "`bar` has a known vulnerability: VULN-2"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "pip-audit"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    assert expected_json == json.loads(sarif_format.format(vuln_data, list()))


def test_sarif_skipped_dep(vuln_data_skipped_dep):
    sarif_format = format.SarifFormat(output_desc=False)
    expected_json = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pip-audit",
                        "informationUri": "https://pypi.org/project/pip-audit/",
                        "rules": [
                            {
                                "id": "VULN-0",
                                "shortDescription": {
                                    "text": "VULN-0"
                                },
                                "helpUri": "https://osv.dev/vulnerability/VULN-0"
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "VULN-0",
                        "level": "error",
                        "message": {
                            "text": "`foo` has a known vulnerability: VULN-0"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "pip-audit"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    assert expected_json == json.loads(sarif_format.format(vuln_data_skipped_dep, list()))
