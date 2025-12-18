"""Tests for range mode data types."""

from datetime import datetime

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from pip_audit._range_types import (
    ConstrainedDependency,
    ConstraintFinding,
    MetadataCoverage,
    UnsatisfiableEnvelope,
    VulnerabilityRangeResult,
)


class TestConstrainedDependency:
    def test_canonical_name(self):
        dep = ConstrainedDependency(
            name="Requests",
            specifier=SpecifierSet(">=2.0"),
            constraint_sources=("pyproject.toml",),
        )
        assert dep.canonical_name == "requests"

    def test_empty_specifier(self):
        dep = ConstrainedDependency(
            name="foo",
            specifier=SpecifierSet(),
            constraint_sources=(),
        )
        assert str(dep.specifier) == ""


class TestVulnerabilityRangeResult:
    def test_basic(self):
        vuln = VulnerabilityRangeResult(
            id="PYSEC-2021-123",
            description="Test vulnerability",
            affected_ranges=(SpecifierSet("<2.0"),),
            fix_versions=[Version("2.0")],
            aliases={"CVE-2021-1234"},
            published=datetime(2021, 1, 1),
        )
        assert vuln.id == "PYSEC-2021-123"
        assert "CVE-2021-1234" in vuln.aliases
        assert vuln.fix_versions[0] == Version("2.0")
        assert vuln.affected_range_display == "<2.0"

    def test_disjoint_ranges_display(self):
        """Test display of disjoint affected ranges (union semantics)."""
        vuln = VulnerabilityRangeResult(
            id="TEST-123",
            description="Test",
            affected_ranges=(SpecifierSet("<1.0"), SpecifierSet(">=2.0,<2.5")),
            fix_versions=[Version("1.0"), Version("2.5")],
            aliases=set(),
        )
        display = vuln.affected_range_display
        # Check structure, not exact string (SpecifierSet order not guaranteed)
        assert display.startswith("(<1.0) OR (")
        assert ">=2.0" in display
        assert "<2.5" in display
        assert " OR " in display


class TestConstraintFinding:
    def test_basic(self):
        dep = ConstrainedDependency(
            name="foo",
            specifier=SpecifierSet(">=1.0"),
            constraint_sources=("pyproject.toml",),
        )
        vuln = VulnerabilityRangeResult(
            id="PYSEC-2021-1",
            description="Test",
            affected_ranges=(SpecifierSet("<1.5"),),
            fix_versions=[Version("1.5")],
            aliases=set(),
        )
        finding = ConstraintFinding(
            dependency=dep,
            vulnerability=vuln,
            vulnerable_versions_permitted=[Version("1.0"), Version("1.1")],
        )
        assert finding.dependency.canonical_name == "foo"
        assert len(finding.vulnerable_versions_permitted) == 2


class TestUnsatisfiableEnvelope:
    def test_basic(self):
        unsat = UnsatisfiableEnvelope(
            name="Foo",
            constraints=(
                (SpecifierSet(">=2.0"), "pyproject.toml"),
                (SpecifierSet("<1.5"), "bar from pyproject.toml"),
            ),
        )
        assert unsat.canonical_name == "foo"
        assert len(unsat.constraints) == 2


class TestMetadataCoverage:
    def test_to_dict(self):
        coverage = MetadataCoverage(
            packages_total=10,
            packages_with_requires_dist=8,
            versions_examined=50,
            versions_with_requires_dist=40,
            versions_no_metadata_available=7,
            versions_fetch_failed=2,
            versions_parse_failed=1,
        )
        d = coverage.to_dict()
        assert d["packages_total"] == 10
        assert d["packages_with_requires_dist"] == 8
        assert d["versions_examined"] == 50
        assert d["versions_with_requires_dist"] == 40
        assert d["versions_no_metadata_available"] == 7
        assert d["versions_fetch_failed"] == 2
        assert d["versions_parse_failed"] == 1
