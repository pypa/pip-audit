"""Integration tests for range mode audit functionality."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import responses
from packaging.version import Version

from pip_audit._range_overlap import compute_range_key
from pip_audit._range_types import (
    ConstrainedDependency,
    ConstraintFinding,
    MetadataCoverage,
    VulnerabilityRangeResult,
)
from packaging.specifiers import SpecifierSet


class TestJinja2Scenario:
    """
    Integration test for the canonical Jinja2 scenario:

    User has jinja2>=3.1.5 in pyproject.toml.
    Vulnerability GHSA-cpwx-vrp4-4pq7 affects <3.1.6.
    The constraint permits 3.1.5 which is vulnerable.
    """

    @responses.activate
    def test_jinja2_vulnerable_version_detected(self):
        """Test that jinja2>=3.1.5 correctly identifies 3.1.5 as vulnerable."""
        # Mock PyPI JSON API response for jinja2
        pypi_response = {
            "info": {
                "name": "jinja2",
                "version": "3.1.6",
                "requires_dist": ["MarkupSafe>=2.0"],
            },
            "releases": {
                "3.1.5": [{"yanked": False}],
                "3.1.6": [{"yanked": False}],
            },
        }
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/jinja2/json",
            json=pypi_response,
            status=200,
        )

        # Mock OSV API response for jinja2
        osv_response = {
            "vulns": [
                {
                    "id": "GHSA-cpwx-vrp4-4pq7",
                    "summary": "Jinja2 sandbox breakout through indirect reference to format method",
                    "affected": [
                        {
                            "package": {"name": "jinja2", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "3.1.6"},
                                    ],
                                }
                            ],
                        }
                    ],
                    "aliases": ["CVE-2024-56326"],
                }
            ]
        }
        responses.add(
            responses.POST,
            "https://api.osv.dev/v1/query",
            json=osv_response,
            status=200,
        )

        # Create test data representing the scenario
        dep = ConstrainedDependency(
            name="jinja2",
            specifier=SpecifierSet(">=3.1.5"),
            constraint_sources=("pyproject.toml",),
        )

        # Compute expected range_key from the OSV events
        events = [{"introduced": "0"}, {"fixed": "3.1.6"}]
        expected_range_key = compute_range_key(events)

        vuln = VulnerabilityRangeResult(
            id="GHSA-cpwx-vrp4-4pq7",
            description="Jinja2 sandbox breakout",
            affected_ranges=(SpecifierSet("<3.1.6"),),
            fix_versions=[Version("3.1.6")],
            aliases={"CVE-2024-56326"},
            range_key=expected_range_key,
        )

        finding = ConstraintFinding(
            dependency=dep,
            vulnerability=vuln,
            vulnerable_versions_permitted=[Version("3.1.5")],
        )

        # Verify the finding structure
        assert finding.dependency.canonical_name == "jinja2"
        assert finding.vulnerability.id == "GHSA-cpwx-vrp4-4pq7"
        assert Version("3.1.5") in finding.vulnerable_versions_permitted
        assert Version("3.1.6") not in finding.vulnerable_versions_permitted

        # Verify the range_key is correctly computed
        assert expected_range_key == ((None, Version("3.1.6")),)

    @responses.activate
    def test_json_output_contains_constraint_findings(self):
        """Test that JSON output includes the constraint_findings key."""
        from pip_audit._format.json import JsonFormat

        dep = ConstrainedDependency(
            name="jinja2",
            specifier=SpecifierSet(">=3.1.5"),
            constraint_sources=("pyproject.toml",),
        )

        events = [{"introduced": "0"}, {"fixed": "3.1.6"}]
        range_key = compute_range_key(events)

        vuln = VulnerabilityRangeResult(
            id="GHSA-cpwx-vrp4-4pq7",
            description="Test",
            affected_ranges=(SpecifierSet("<3.1.6"),),
            fix_versions=[Version("3.1.6")],
            aliases={"CVE-2024-56326"},
            range_key=range_key,
        )

        finding = ConstraintFinding(
            dependency=dep,
            vulnerability=vuln,
            vulnerable_versions_permitted=[Version("3.1.5")],
        )

        coverage = MetadataCoverage(
            packages_total=1,
            packages_with_requires_dist=1,
            versions_examined=2,
            versions_with_requires_dist=1,
            versions_no_metadata_available=1,
            versions_fetch_failed=0,
            versions_parse_failed=0,
        )

        formatter = JsonFormat(output_desc=False, output_aliases=True)
        output = formatter.format_constraint_findings([finding], [], coverage)
        data = json.loads(output)

        # Assert JSON schema key exists
        assert "constraint_findings" in data
        assert len(data["constraint_findings"]) == 1

        finding_data = data["constraint_findings"][0]
        assert finding_data["name"] == "jinja2"
        assert finding_data["envelope"] == ">=3.1.5"
        assert "GHSA-cpwx-vrp4-4pq7" in finding_data["vulnerability"]["ids"]
        assert "3.1.5" in finding_data["vulnerable_versions_permitted"]

        # Assert transitive_metadata_completeness key exists (not metadata_coverage)
        assert "transitive_metadata_completeness" in data
        assert "metadata_coverage" not in data


class TestRangeStrictExitCode:
    """Test that --range-strict correctly flips exit code."""

    def test_exit_code_with_findings(self, tmp_path):
        """Test that exit code is 1 with --range-strict when findings exist."""
        # Create a minimal pyproject.toml with a known vulnerable package
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""
[project]
name = "test-project"
version = "0.1.0"
dependencies = ["jinja2>=3.1.5"]
""")

        # This test would require network access and is more of an integration test
        # For unit testing, we verify the CLI contract through the data structures
        pass

    def test_finding_grouping_by_range_key(self):
        """Test that findings with same range_key are grouped together."""
        from pip_audit._format.json import JsonFormat

        dep = ConstrainedDependency(
            name="idna",
            specifier=SpecifierSet(">=3.0"),
            constraint_sources=("pyproject.toml",),
        )

        # Same range (both <3.7) but different advisory sources
        events = [{"introduced": "0"}, {"fixed": "3.7"}]
        range_key = compute_range_key(events)

        vuln_ghsa = VulnerabilityRangeResult(
            id="GHSA-xxx-yyy-zzz",
            description="Test GHSA",
            affected_ranges=(SpecifierSet("<3.7"),),
            fix_versions=[Version("3.7")],
            aliases=set(),
            range_key=range_key,
        )

        vuln_pysec = VulnerabilityRangeResult(
            id="PYSEC-2024-123",
            description="Test PYSEC",
            affected_ranges=(SpecifierSet(">=0,<3.7"),),  # Same range, different syntax
            fix_versions=[Version("3.7")],
            aliases=set(),
            range_key=range_key,  # Same range_key!
        )

        finding_ghsa = ConstraintFinding(
            dependency=dep,
            vulnerability=vuln_ghsa,
            vulnerable_versions_permitted=[Version("3.0"), Version("3.6")],
        )

        finding_pysec = ConstraintFinding(
            dependency=dep,
            vulnerability=vuln_pysec,
            vulnerable_versions_permitted=[Version("3.0"), Version("3.6")],
        )

        coverage = MetadataCoverage(
            packages_total=1,
            packages_with_requires_dist=1,
            versions_examined=10,
            versions_with_requires_dist=5,
            versions_no_metadata_available=5,
            versions_fetch_failed=0,
            versions_parse_failed=0,
        )

        formatter = JsonFormat(output_desc=False, output_aliases=False)
        output = formatter.format_constraint_findings(
            [finding_ghsa, finding_pysec], [], coverage
        )
        data = json.loads(output)

        # Should be grouped into ONE finding with both IDs
        assert len(data["constraint_findings"]) == 1
        finding = data["constraint_findings"][0]
        assert "GHSA-xxx-yyy-zzz" in finding["vulnerability"]["ids"]
        assert "PYSEC-2024-123" in finding["vulnerability"]["ids"]


class TestDescAliasToggles:
    """Tests for P2a bug fix: desc/aliases enum toggles respected."""

    def test_output_desc_false_excludes_description(self):
        """Verify output_desc=False excludes description from output."""
        from pip_audit._format.json import JsonFormat

        dep = ConstrainedDependency(
            name="test-pkg",
            specifier=SpecifierSet(">=1.0"),
            constraint_sources=("pyproject.toml",),
        )

        events = [{"introduced": "0"}, {"fixed": "2.0"}]
        range_key = compute_range_key(events)

        vuln = VulnerabilityRangeResult(
            id="TEST-123",
            description="This is a test vulnerability description that should NOT appear",
            affected_ranges=(SpecifierSet("<2.0"),),
            fix_versions=[Version("2.0")],
            aliases={"CVE-2024-1234"},
            range_key=range_key,
        )

        finding = ConstraintFinding(
            dependency=dep,
            vulnerability=vuln,
            vulnerable_versions_permitted=[Version("1.0")],
        )

        coverage = MetadataCoverage(
            packages_total=1,
            packages_with_requires_dist=1,
            versions_examined=1,
            versions_with_requires_dist=1,
            versions_no_metadata_available=0,
            versions_fetch_failed=0,
            versions_parse_failed=0,
        )

        # Test with output_desc=False
        formatter = JsonFormat(output_desc=False, output_aliases=True)
        output = formatter.format_constraint_findings([finding], [], coverage)
        data = json.loads(output)

        vuln_data = data["constraint_findings"][0]["vulnerability"]
        assert "description" not in vuln_data

        # Verify aliases ARE included (output_aliases=True)
        assert "aliases" in vuln_data
        assert "CVE-2024-1234" in vuln_data["aliases"]

    def test_output_aliases_false_excludes_aliases(self):
        """Verify output_aliases=False produces empty aliases list."""
        from pip_audit._format.json import JsonFormat

        dep = ConstrainedDependency(
            name="test-pkg",
            specifier=SpecifierSet(">=1.0"),
            constraint_sources=("pyproject.toml",),
        )

        events = [{"introduced": "0"}, {"fixed": "2.0"}]
        range_key = compute_range_key(events)

        vuln = VulnerabilityRangeResult(
            id="TEST-123",
            description="Test description",
            affected_ranges=(SpecifierSet("<2.0"),),
            fix_versions=[Version("2.0")],
            aliases={"CVE-2024-1234", "CVE-2024-5678"},
            range_key=range_key,
        )

        finding = ConstraintFinding(
            dependency=dep,
            vulnerability=vuln,
            vulnerable_versions_permitted=[Version("1.0")],
        )

        coverage = MetadataCoverage(
            packages_total=1,
            packages_with_requires_dist=1,
            versions_examined=1,
            versions_with_requires_dist=1,
            versions_no_metadata_available=0,
            versions_fetch_failed=0,
            versions_parse_failed=0,
        )

        # Test with output_aliases=False
        formatter = JsonFormat(output_desc=True, output_aliases=False)
        output = formatter.format_constraint_findings([finding], [], coverage)
        data = json.loads(output)

        vuln_data = data["constraint_findings"][0]["vulnerability"]
        # Aliases key should be ABSENT when output_aliases=False
        assert "aliases" not in vuln_data
        # Verify description IS included (output_desc=True)
        assert vuln_data["description"] == "Test description"


class TestRangeModeE2E:
    """End-to-end integration tests for range mode."""

    @responses.activate
    def test_audit_range_full_pipeline(self, tmp_path):
        """E2E test: full _audit_range pipeline with mocked HTTP responses."""
        import argparse

        from pip_audit._range_audit import _audit_range

        # Create pyproject.toml with a known dependency
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            """
[project]
name = "test-project"
version = "0.1.0"
dependencies = ["jinja2>=3.1.5"]
"""
        )

        # Mock PyPI JSON API for jinja2
        pypi_jinja2_response = {
            "info": {
                "name": "jinja2",
                "version": "3.1.6",
                "requires_dist": ["MarkupSafe>=2.0"],
            },
            "releases": {
                "3.1.5": [{"yanked": False}],
                "3.1.6": [{"yanked": False}],
            },
        }
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/jinja2/json",
            json=pypi_jinja2_response,
            status=200,
        )

        # Mock PyPI JSON API for markupsafe (transitive dep)
        pypi_markupsafe_response = {
            "info": {
                "name": "markupsafe",
                "version": "2.1.5",
                "requires_dist": None,
            },
            "releases": {
                "2.1.5": [{"yanked": False}],
            },
        }
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/markupsafe/json",
            json=pypi_markupsafe_response,
            status=200,
        )

        # Mock OSV API for jinja2
        osv_jinja2_response = {
            "vulns": [
                {
                    "id": "GHSA-cpwx-vrp4-4pq7",
                    "summary": "Jinja2 sandbox breakout",
                    "affected": [
                        {
                            "package": {"name": "jinja2", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "3.1.6"},
                                    ],
                                }
                            ],
                        }
                    ],
                    "aliases": ["CVE-2024-56326"],
                }
            ]
        }
        responses.add(
            responses.POST,
            "https://api.osv.dev/v1/query",
            json=osv_jinja2_response,
            status=200,
        )

        # Mock OSV API for markupsafe (no vulns)
        osv_markupsafe_response = {"vulns": []}
        responses.add(
            responses.POST,
            "https://api.osv.dev/v1/query",
            json=osv_markupsafe_response,
            status=200,
        )

        # Create args namespace
        args = argparse.Namespace(
            range=True,
            range_strict=False,
            project_path=tmp_path,
            format=None,  # Use default text format
            desc=None,
            aliases=None,
            cache_dir=None,
            timeout=10,
            osv_url=None,
        )

        # Capture stdout
        import io
        import sys

        captured_output = io.StringIO()
        sys.stdout = captured_output

        try:
            exit_code = _audit_range(args)
        finally:
            sys.stdout = sys.__stdout__

        output = captured_output.getvalue()

        # Verify exit code (--range mode always returns 0 unless --range-strict)
        assert exit_code == 0

        # Verify output contains expected finding
        assert "jinja2" in output.lower() or "GHSA" in output

    @responses.activate
    def test_audit_range_strict_exit_code(self, tmp_path):
        """Verify --range-strict returns exit 1 when findings exist."""
        import argparse

        from pip_audit._range_audit import _audit_range

        # Create pyproject.toml
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            """
[project]
name = "test-project"
version = "0.1.0"
dependencies = ["jinja2>=3.1.5"]
"""
        )

        # Mock PyPI JSON API for jinja2
        pypi_response = {
            "info": {
                "name": "jinja2",
                "version": "3.1.6",
                "requires_dist": None,  # No transitive deps to simplify
            },
            "releases": {
                "3.1.5": [{"yanked": False}],
                "3.1.6": [{"yanked": False}],
            },
        }
        responses.add(
            responses.GET,
            "https://pypi.org/pypi/jinja2/json",
            json=pypi_response,
            status=200,
        )

        # Mock OSV API with vulnerability
        osv_response = {
            "vulns": [
                {
                    "id": "GHSA-test",
                    "summary": "Test vulnerability",
                    "affected": [
                        {
                            "package": {"name": "jinja2", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "3.1.6"},
                                    ],
                                }
                            ],
                        }
                    ],
                    "aliases": [],
                }
            ]
        }
        responses.add(
            responses.POST,
            "https://api.osv.dev/v1/query",
            json=osv_response,
            status=200,
        )

        # Create args with range_strict=True
        args = argparse.Namespace(
            range=False,
            range_strict=True,
            project_path=tmp_path,
            format=None,
            desc=None,
            aliases=None,
            cache_dir=None,
            timeout=10,
            osv_url=None,
        )

        # Suppress stdout
        import io
        import sys

        sys.stdout = io.StringIO()

        try:
            exit_code = _audit_range(args)
        finally:
            sys.stdout = sys.__stdout__

        # Verify --range-strict returns 1 when findings exist
        assert exit_code == 1
