import json
import xml.etree.ElementTree as ET

import pretend  # type: ignore
import pytest

from pip_audit._format import CycloneDxFormat


@pytest.mark.parametrize(
    "inner", [CycloneDxFormat.InnerFormat.Xml, CycloneDxFormat.InnerFormat.Json]
)
def test_cyclonedx_manifest(inner):
    fmt = CycloneDxFormat(inner_format=inner)
    assert fmt.is_manifest


def test_cyclonedx_inner_json(vuln_data):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)

    # We don't test CycloneDX's formatting/layout decisions, only that
    # the formatter emits correct JSON when initialized in JSON mode.
    assert json.loads(formatter.format(vuln_data, list())) is not None


def test_cyclonedx_inner_xml(vuln_data):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Xml)

    # We don't test CycloneDX's formatting/layout decisions, only that
    # the formatter emits correct XML when initialized in XML mode.
    assert ET.fromstring(formatter.format(vuln_data, list())) is not None


def test_cyclonedx_skipped_dep(vuln_data_skipped_dep):
    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)

    # Just test that a skipped dependency doesn't cause the formatter to blow up
    assert json.loads(formatter.format(vuln_data_skipped_dep, list())) is not None


def test_cyclonedx_fix(monkeypatch, vuln_data, fix_data):
    import pip_audit._format.cyclonedx as cyclonedx

    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(cyclonedx, "logger", logger)

    formatter = CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
    assert json.loads(formatter.format(vuln_data, fix_data)) is not None

    # The CycloneDX format doesn't support fixes so we expect to log a warning
    assert len(logger.warning.calls) == 1
