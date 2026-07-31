import json

import pretend  # type: ignore
import pytest

import pip_audit._format as format
from pip_audit import __version__


@pytest.mark.parametrize(
    ("output_desc", "output_aliases"),
    ([True, False], [False, True], [True, True], [False, False]),
)
def test_sarif_manifest(output_desc, output_aliases):
    fmt = format.SarifFormat(output_desc, output_aliases)

    assert fmt.is_manifest


def test_sarif(vuln_data):
    sarif_format = format.SarifFormat(True, True)
    payload = json.loads(sarif_format.format(vuln_data, []))

    assert payload["version"] == "2.1.0"
    assert payload["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert len(payload["runs"]) == 1

    run = payload["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "pip-audit"
    assert driver["version"] == __version__
    assert driver["informationUri"] == "https://github.com/pypa/pip-audit"

    rule_ids = {rule["id"] for rule in driver["rules"]}
    assert rule_ids == {"VULN-0", "VULN-1", "VULN-2"}

    vuln0 = next(rule for rule in driver["rules"] if rule["id"] == "VULN-0")
    assert vuln0["fullDescription"]["text"] == "The first vulnerability"
    assert vuln0["helpUri"] == "https://osv.dev/vulnerability/VULN-0"
    assert vuln0["properties"]["aliases"] == ["CVE-0000-00000"]
    assert vuln0["properties"]["fix_versions"] == ["1.1", "1.4"]

    assert len(run["results"]) == 3
    first = run["results"][0]
    assert first["ruleId"] == "VULN-0"
    assert first["level"] == "error"
    assert first["properties"]["package"] == "foo"
    assert first["properties"]["version"] == "1.0"
    assert "physicalLocation" not in first
    assert "locations" not in first


def test_sarif_no_desc_no_aliases(vuln_data):
    sarif_format = format.SarifFormat(False, False)
    payload = json.loads(sarif_format.format(vuln_data, []))
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    vuln0 = next(rule for rule in rules if rule["id"] == "VULN-0")

    assert "fullDescription" not in vuln0
    assert vuln0["shortDescription"]["text"] == "VULN-0"
    assert "aliases" not in vuln0.get("properties", {})
    assert vuln0["properties"]["fix_versions"] == ["1.1", "1.4"]


def test_sarif_skipped_dep(vuln_data_skipped_dep):
    sarif_format = format.SarifFormat(False, True)
    payload = json.loads(sarif_format.format(vuln_data_skipped_dep, []))

    assert len(payload["runs"][0]["results"]) == 1
    assert payload["runs"][0]["results"][0]["ruleId"] == "VULN-0"
    assert {rule["id"] for rule in payload["runs"][0]["tool"]["driver"]["rules"]} == {"VULN-0"}


def test_sarif_fix_unsupported(vuln_data, fix_data, monkeypatch):
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(format.sarif, "logger", logger)

    sarif_format = format.SarifFormat(True, True)
    payload = json.loads(sarif_format.format(vuln_data, fix_data))

    assert len(payload["runs"][0]["results"]) == 3
    assert len(logger.warning.calls) == 1
