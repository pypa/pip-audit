from pathlib import Path

import pretend  # type: ignore
import pytest

import pip_audit._cli
from pip_audit._cli import (
    OutputFormatChoice,
    ProgressSpinnerChoice,
    VulnerabilityAliasChoice,
    VulnerabilityDescriptionChoice,
    VulnerabilityServiceChoice,
)


class TestOutputFormatChoice:
    def test_to_format_is_exhaustive(self):
        for choice in OutputFormatChoice:
            assert choice.to_format(False, False) is not None
            assert choice.to_format(True, True) is not None
            assert choice.to_format(False, True) is not None
            assert choice.to_format(True, False) is not None

    def test_str(self):
        for choice in OutputFormatChoice:
            assert str(choice) == choice.value


class TestVulnerabilityServiceChoice:
    def test_str(self):
        for choice in VulnerabilityServiceChoice:
            assert str(choice) == choice.value


class TestVulnerabilityDescriptionChoice:
    def test_to_bool_is_exhaustive(self):
        for choice in VulnerabilityDescriptionChoice:
            assert choice.to_bool(OutputFormatChoice.Json) in {True, False}

    def test_auto_to_bool_for_json(self):
        assert VulnerabilityDescriptionChoice.Auto.to_bool(OutputFormatChoice.Json) is True

    def test_str(self):
        for choice in VulnerabilityDescriptionChoice:
            assert str(choice) == choice.value


class TestVulnerabilityAliasChoice:
    def test_to_bool_is_exhaustive(self):
        for choice in VulnerabilityAliasChoice:
            assert choice.to_bool(OutputFormatChoice.Json) in {True, False}
            assert choice.to_bool(OutputFormatChoice.Markdown) in {True, False}
            assert choice.to_bool(OutputFormatChoice.Columns) in {True, False}
            assert choice.to_bool(OutputFormatChoice.CycloneDxJson) in {True, False}
            assert choice.to_bool(OutputFormatChoice.CycloneDxXml) in {True, False}

    def test_auto_to_bool_for_json(self):
        assert VulnerabilityAliasChoice.Auto.to_bool(OutputFormatChoice.Json) is True

    def test_str(self):
        for choice in VulnerabilityAliasChoice:
            assert str(choice) == choice.value


class TestProgressSpinnerChoice:
    def test_bool(self):
        assert bool(ProgressSpinnerChoice.On)
        assert not bool(ProgressSpinnerChoice.Off)

    def test_str(self):
        for choice in ProgressSpinnerChoice:
            assert str(choice) == choice.value


@pytest.mark.parametrize(
    "args, vuln_count, pkg_count, expected",
    [
        ([], 1, 1, "Found 1 known vulnerability in 1 package"),
        ([], 2, 1, "Found 2 known vulnerabilities in 1 package"),
        ([], 2, 2, "Found 2 known vulnerabilities in 2 packages"),
        (
            ["--ignore-vuln", "bar"],
            2,
            2,
            "Found 2 known vulnerabilities, ignored 1 in 2 packages",
        ),
        (["--fix"], 1, 1, "fixed 1 vulnerability in 1 package"),
        (["--fix"], 2, 1, "fixed 2 vulnerabilities in 1 package"),
        (["--fix"], 2, 2, "fixed 2 vulnerabilities in 2 packages"),
        ([], 0, 0, "No known vulnerabilities found"),
        (["--ignore-vuln", "bar"], 0, 1, "No known vulnerabilities found, 1 ignored"),
    ],
)
def test_plurals(capsys, monkeypatch, args, vuln_count, pkg_count, expected):
    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(args))

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="something" + str(i),
                canonical_name="something" + str(i),
                version=1,
            ),
            [
                pretend.stub(
                    fix_versions=[2],
                    id="foo",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ]
            * (vuln_count // pkg_count),
        )
        for i in range(pkg_count)
    ]

    if "--ignore-vuln" in args:
        result[0][1].append(pretend.stub(id="bar", aliases=set(), has_any_id=lambda x: True))

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=2) for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    captured = capsys.readouterr()
    assert expected in captured.err


@pytest.mark.parametrize(
    "vuln_count, pkg_count, skip_count, print_format",
    [
        (1, 1, 0, True),
        (2, 1, 0, True),
        (2, 2, 0, True),
        (0, 0, 0, False),
        (0, 1, 0, False),
        # If there are no vulnerabilities but a dependency has been skipped, we
        # should print the formatted result
        (0, 0, 1, True),
    ],
)
def test_print_format(monkeypatch, vuln_count, pkg_count, skip_count, print_format):
    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    dummyformat = pretend.stub(
        format=pretend.call_recorder(lambda _result, _fixes: None),
        is_manifest=False,
    )
    monkeypatch.setattr(pip_audit._cli, "ColumnsFormat", lambda *a, **kw: dummyformat)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args([]))

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="something" + str(i),
                canonical_name="something" + str(i),
                version=1,
            ),
            [
                pretend.stub(
                    fix_versions=[2],
                    id="foo",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ]
            * (vuln_count // pkg_count),
        )
        for i in range(pkg_count)
    ]
    result.extend(
        (
            pretend.stub(
                is_skipped=lambda: True,
                name="skipped " + str(i),
                canonical_name="skipped " + str(i),
                version=1,
                skip_reason="reason " + str(i),
            ),
            [],
        )
        for i in range(skip_count)
    )

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=2) for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    assert bool(dummyformat.format.calls) == print_format


def test_environment_variable(monkeypatch):
    """Environment variables set before execution change CLI option default."""
    monkeypatch.setenv("PIP_AUDIT_DESC", "off")
    monkeypatch.setenv("PIP_AUDIT_FORMAT", "markdown")
    monkeypatch.setenv("PIP_AUDIT_OUTPUT", "/tmp/fake")
    monkeypatch.setenv("PIP_AUDIT_PROGRESS_SPINNER", "off")
    monkeypatch.setenv("PIP_AUDIT_VULNERABILITY_SERVICE", "osv")

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args([]))
    args = pip_audit._cli._parse_args(parser, [])

    assert args.desc == VulnerabilityDescriptionChoice.Off
    assert args.format == OutputFormatChoice.Markdown
    assert args.output == Path("/tmp/fake")
    assert not args.progress_spinner
    assert args.vulnerability_service == VulnerabilityServiceChoice.Osv


def test_cyclonedx_single_output(tmp_path, monkeypatch):
    """Test --cyclonedx with a single JSON output file."""
    output_file = tmp_path / "sbom.json"

    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(
        pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(["--cyclonedx", str(output_file)])
    )

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="package1",
                canonical_name="package1",
                version=1,
            ),
            [
                pretend.stub(
                    fix_versions=[2],
                    id="VULN-001",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ],
        )
    ]

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=2) for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    assert output_file.exists()
    content = output_file.read_text()
    assert len(content) > 0
    # Basic check that it's JSON-like
    assert content.startswith("{") or content.startswith("[")


def test_cyclonedx_multiple_outputs(tmp_path, monkeypatch):
    """Test --cyclonedx with multiple output files (JSON and XML)."""
    json_file = tmp_path / "sbom.json"
    xml_file = tmp_path / "sbom.xml"

    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(
        pip_audit._cli,
        "_parse_args",
        lambda *a: parser.parse_args(
            ["--cyclonedx", str(json_file), "--cyclonedx", str(xml_file)]
        ),
    )

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="package1",
                canonical_name="package1",
                version=1,
            ),
            [
                pretend.stub(
                    fix_versions=[2],
                    id="VULN-001",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ],
        )
    ]

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=2) for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    assert json_file.exists()
    assert xml_file.exists()

    json_content = json_file.read_text()
    xml_content = xml_file.read_text()

    assert len(json_content) > 0
    assert len(xml_content) > 0

    # Basic format checks
    assert json_content.startswith("{") or json_content.startswith("[")
    assert xml_content.startswith("<?xml") or xml_content.startswith("<")


def test_cyclonedx_with_regular_output(tmp_path, monkeypatch):
    """Test --cyclonedx used alongside regular --output."""
    regular_output = tmp_path / "output.txt"
    cyclonedx_output = tmp_path / "sbom.json"

    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(
        pip_audit._cli,
        "_parse_args",
        lambda *a: parser.parse_args(
            ["--output", str(regular_output), "--cyclonedx", str(cyclonedx_output)]
        ),
    )

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="package1",
                canonical_name="package1",
                version=1,
            ),
            [
                pretend.stub(
                    fix_versions=[2],
                    id="VULN-001",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ],
        )
    ]

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=2) for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    assert regular_output.exists()
    assert cyclonedx_output.exists()


def test_cyclonedx_invalid_extension(monkeypatch):
    """Test --cyclonedx with invalid file extension."""
    parser = pip_audit._cli._parser()

    with pytest.raises(SystemExit):
        pip_audit._cli._parse_args(parser, ["--cyclonedx", "sbom.txt"])


def test_cyclonedx_no_vulnerabilities(tmp_path, monkeypatch):
    """Test --cyclonedx outputs manifest even when no vulnerabilities found."""
    output_file = tmp_path / "sbom.json"

    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(
        pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(["--cyclonedx", str(output_file)])
    )

    # No vulnerabilities
    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="package1",
                canonical_name="package1",
                version=1,
            ),
            [],
        )
    ]

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = []
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    # CycloneDX is a manifest format, should be written even with no vulnerabilities
    assert output_file.exists()
    content = output_file.read_text()
    assert len(content) > 0
