"""Tests for range overlap detection."""

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from pip_audit._range_overlap import compute_range_key, ranges_overlap, specifier_from_osv_range


class TestRangesOverlap:
    def test_simple_overlap(self):
        allowed = SpecifierSet(">=1.0,<2.0")
        vulnerable = SpecifierSet("<1.5")
        known_versions = [Version(v) for v in ["0.9", "1.0", "1.1", "1.4", "1.5", "2.0"]]

        overlaps, versions = ranges_overlap(allowed, vulnerable, known_versions)

        assert overlaps
        assert Version("1.0") in versions
        assert Version("1.1") in versions
        assert Version("1.4") in versions
        assert Version("1.5") not in versions  # Not in vulnerable range
        assert Version("0.9") not in versions  # Not in allowed range

    def test_no_overlap(self):
        allowed = SpecifierSet(">=2.0")
        vulnerable = SpecifierSet("<1.5")
        known_versions = [Version(v) for v in ["1.0", "1.4", "2.0", "2.1"]]

        overlaps, versions = ranges_overlap(allowed, vulnerable, known_versions)

        assert not overlaps
        assert versions == []

    def test_yanked_excluded(self):
        allowed = SpecifierSet(">=1.0")
        vulnerable = SpecifierSet("<2.0")
        known_versions = [Version(v) for v in ["1.0", "1.5", "1.9"]]
        yanked = {Version("1.5")}

        overlaps, versions = ranges_overlap(
            allowed, vulnerable, known_versions, yanked_versions=yanked
        )

        assert overlaps
        assert Version("1.0") in versions
        assert Version("1.5") not in versions  # Yanked
        assert Version("1.9") in versions

    def test_prereleases_excluded_by_default(self):
        allowed = SpecifierSet(">=1.0")
        vulnerable = SpecifierSet("<2.0")
        known_versions = [Version(v) for v in ["1.0", "1.5a1", "1.5", "2.0a1"]]

        overlaps, versions = ranges_overlap(allowed, vulnerable, known_versions)

        assert overlaps
        assert Version("1.0") in versions
        assert Version("1.5a1") not in versions  # Prerelease excluded
        assert Version("1.5") in versions

    def test_prereleases_included_when_specifier_admits(self):
        # When specifier explicitly includes prereleases like >=1.0a1
        allowed = SpecifierSet(">=1.0a1")
        vulnerable = SpecifierSet("<2.0")
        known_versions = [Version(v) for v in ["1.0a1", "1.0", "1.5"]]

        overlaps, versions = ranges_overlap(
            allowed, vulnerable, known_versions, include_prereleases=True
        )

        assert overlaps
        assert Version("1.0a1") in versions

    def test_empty_allowed_matches_all(self):
        allowed = SpecifierSet()  # Empty = all versions
        vulnerable = SpecifierSet("<1.5")
        known_versions = [Version(v) for v in ["1.0", "1.4", "2.0"]]

        overlaps, versions = ranges_overlap(allowed, vulnerable, known_versions)

        assert overlaps
        assert Version("1.0") in versions
        assert Version("1.4") in versions
        assert Version("2.0") not in versions  # Not vulnerable

    def test_disjoint_vulnerable_ranges_union(self):
        """Test that disjoint vulnerable ranges use union semantics (not intersection)."""
        allowed = SpecifierSet(">=0.5")
        # Disjoint vulnerable ranges: <1.0 OR >=2.0,<2.5
        vulnerable_ranges = (SpecifierSet("<1.0"), SpecifierSet(">=2.0,<2.5"))
        known_versions = [Version(v) for v in ["0.5", "0.9", "1.5", "2.0", "2.3", "3.0"]]

        overlaps, versions = ranges_overlap(allowed, vulnerable_ranges, known_versions)

        assert overlaps
        # 0.5 and 0.9 are in <1.0 range
        assert Version("0.5") in versions
        assert Version("0.9") in versions
        # 1.5 is not in either vulnerable range
        assert Version("1.5") not in versions
        # 2.0 and 2.3 are in >=2.0,<2.5 range
        assert Version("2.0") in versions
        assert Version("2.3") in versions
        # 3.0 is not in either vulnerable range
        assert Version("3.0") not in versions

    def test_single_vulnerable_range_backwards_compat(self):
        """Test that a single SpecifierSet still works (backwards compat)."""
        allowed = SpecifierSet(">=1.0")
        vulnerable = SpecifierSet("<1.5")  # Single SpecifierSet, not tuple
        known_versions = [Version(v) for v in ["1.0", "1.4", "1.5"]]

        overlaps, versions = ranges_overlap(allowed, vulnerable, known_versions)

        assert overlaps
        assert Version("1.0") in versions
        assert Version("1.4") in versions
        assert Version("1.5") not in versions


class TestSpecifierFromOsvRange:
    """Tests for specifier_from_osv_range which returns tuple[SpecifierSet, ...]."""

    def test_simple_introduced_fixed(self):
        events = [{"introduced": "1.0"}, {"fixed": "1.5"}]
        specs = specifier_from_osv_range(events)
        assert len(specs) == 1
        spec = specs[0]
        assert spec.contains(Version("1.0"))
        assert spec.contains(Version("1.4"))
        assert not spec.contains(Version("1.5"))
        assert not spec.contains(Version("0.9"))

    def test_introduced_zero(self):
        events = [{"introduced": "0"}, {"fixed": "2.0"}]
        specs = specifier_from_osv_range(events)
        assert len(specs) == 1
        spec = specs[0]
        assert spec.contains(Version("0.1"))
        assert spec.contains(Version("1.9"))
        assert not spec.contains(Version("2.0"))

    def test_no_fix(self):
        events = [{"introduced": "1.0"}]
        specs = specifier_from_osv_range(events)
        assert len(specs) == 1
        spec = specs[0]
        assert spec.contains(Version("1.0"))
        assert spec.contains(Version("999.0"))

    def test_empty_events(self):
        events = []
        specs = specifier_from_osv_range(events)
        assert specs == ()  # Empty tuple

    def test_disjoint_ranges_within_single_entry(self):
        """
        Test that disjoint intervals in one OSV entry produce multiple SpecifierSets.

        This is the P1 bug fix test: events like
        [introduced:1.0, fixed:1.5, introduced:2.0, fixed:2.5]
        should produce TWO specs (union), not one AND'd spec.
        """
        events = [
            {"introduced": "1.0"},
            {"fixed": "1.5"},
            {"introduced": "2.0"},
            {"fixed": "2.5"},
        ]
        specs = specifier_from_osv_range(events)

        # Should return TWO separate specs (union semantics)
        assert len(specs) == 2

        # First interval: >=1.0,<1.5
        assert specs[0].contains(Version("1.0"))
        assert specs[0].contains(Version("1.4"))
        assert not specs[0].contains(Version("1.5"))
        assert not specs[0].contains(Version("2.0"))

        # Second interval: >=2.0,<2.5
        assert specs[1].contains(Version("2.0"))
        assert specs[1].contains(Version("2.4"))
        assert not specs[1].contains(Version("2.5"))
        assert not specs[1].contains(Version("1.0"))

    def test_disjoint_with_open_end(self):
        """Test disjoint ranges where the last one has no fix."""
        events = [
            {"introduced": "1.0"},
            {"fixed": "1.5"},
            {"introduced": "3.0"},
            # No fix for 3.0+ means open-ended
        ]
        specs = specifier_from_osv_range(events)

        assert len(specs) == 2
        # First: >=1.0,<1.5
        assert specs[0].contains(Version("1.0"))
        assert not specs[0].contains(Version("1.5"))
        # Second: >=3.0 (open-ended)
        assert specs[1].contains(Version("3.0"))
        assert specs[1].contains(Version("999.0"))


class TestComputeRangeKey:
    def test_zero_introduced_fixed(self):
        """>=0,<3.7 should normalize to (None, 3.7)"""
        events = [{"introduced": "0"}, {"fixed": "3.7"}]
        key = compute_range_key(events)
        assert len(key) == 1
        assert key[0][0] is None  # Lower bound is -∞
        assert key[0][1] == Version("3.7")

    def test_version_introduced_fixed(self):
        """>=1.0,<1.5 should normalize to (1.0, 1.5)"""
        events = [{"introduced": "1.0"}, {"fixed": "1.5"}]
        key = compute_range_key(events)
        assert len(key) == 1
        assert key[0][0] == Version("1.0")
        assert key[0][1] == Version("1.5")

    def test_open_range(self):
        """>=1.0 with no fix should normalize to (1.0, None)"""
        events = [{"introduced": "1.0"}]
        key = compute_range_key(events)
        assert len(key) == 1
        assert key[0][0] == Version("1.0")
        assert key[0][1] is None  # Upper bound is +∞

    def test_zero_dot_zero_treated_as_infinity(self):
        """>=0.0 should be treated as -∞"""
        events = [{"introduced": "0.0"}, {"fixed": "2.0"}]
        key = compute_range_key(events)
        assert len(key) == 1
        assert key[0][0] is None  # Normalized to -∞
        assert key[0][1] == Version("2.0")

    def test_zero_dot_zero_dot_zero(self):
        """>=0.0.0 should be treated as -∞"""
        events = [{"introduced": "0.0.0"}, {"fixed": "1.0"}]
        key = compute_range_key(events)
        assert key[0][0] is None

    def test_empty_events(self):
        """Empty events should produce empty key"""
        key = compute_range_key([])
        assert key == ()

    def test_equivalent_ranges_same_key(self):
        """>=0,<3.7 and <3.7 should produce same key after normalization"""
        events1 = [{"introduced": "0"}, {"fixed": "3.7"}]
        events2 = [{"introduced": "0.0"}, {"fixed": "3.7"}]
        key1 = compute_range_key(events1)
        key2 = compute_range_key(events2)
        assert key1 == key2


class TestOsvParsingEdgeCases:
    """Tests for OSV parsing edge cases and bug fixes."""

    def test_consecutive_introduced_events(self):
        """
        Regression test: consecutive introduced events without fixed should use first.

        Per OSV spec, once a version is introduced as affected, it stays affected
        until a fixed event closes the interval. Multiple introduced events in
        a row should not overwrite the first one.
        """
        events = [{"introduced": "1.0"}, {"introduced": "1.2"}, {"fixed": "1.5"}]
        specs = specifier_from_osv_range(events)

        # Should emit >=1.0,<1.5 (not >=1.2,<1.5)
        assert len(specs) == 1
        assert specs[0].contains(Version("1.0"))
        assert specs[0].contains(Version("1.1"))  # Was missed before fix
        assert specs[0].contains(Version("1.2"))
        assert specs[0].contains(Version("1.4"))
        assert not specs[0].contains(Version("1.5"))
        assert not specs[0].contains(Version("0.9"))

    def test_consecutive_introduced_with_zero(self):
        """Regression: consecutive introduced with zero as first."""
        events = [{"introduced": "0"}, {"introduced": "1.0"}, {"fixed": "2.0"}]
        specs = specifier_from_osv_range(events)

        # Should emit <2.0 (using "0" as start, not "1.0")
        assert len(specs) == 1
        assert specs[0].contains(Version("0.1"))
        assert specs[0].contains(Version("1.0"))
        assert specs[0].contains(Version("1.9"))
        assert not specs[0].contains(Version("2.0"))

    def test_last_affected_event(self):
        """Handle last_affected event type from OSV spec."""
        events = [{"introduced": "1.0"}, {"last_affected": "1.4"}]
        specs = specifier_from_osv_range(events)

        assert len(specs) == 1
        # last_affected is INCLUSIVE
        assert specs[0].contains(Version("1.0"))
        assert specs[0].contains(Version("1.4"))  # Inclusive
        assert not specs[0].contains(Version("1.5"))
        assert not specs[0].contains(Version("0.9"))

    def test_last_affected_with_zero_introduced(self):
        """Handle last_affected with unbounded lower."""
        events = [{"introduced": "0"}, {"last_affected": "2.0"}]
        specs = specifier_from_osv_range(events)

        assert len(specs) == 1
        # <=2.0 (all versions from beginning up to and including 2.0)
        assert specs[0].contains(Version("0.1"))
        assert specs[0].contains(Version("1.5"))
        assert specs[0].contains(Version("2.0"))  # Inclusive
        assert not specs[0].contains(Version("2.1"))

    def test_last_affected_multiple_intervals(self):
        """Handle last_affected in multiple interval scenario."""
        events = [
            {"introduced": "1.0"},
            {"last_affected": "1.5"},
            {"introduced": "2.0"},
            {"fixed": "2.5"},
        ]
        specs = specifier_from_osv_range(events)

        # Two intervals: >=1.0,<=1.5 and >=2.0,<2.5
        assert len(specs) == 2

        # First interval: >=1.0,<=1.5
        assert specs[0].contains(Version("1.0"))
        assert specs[0].contains(Version("1.5"))  # Inclusive
        assert not specs[0].contains(Version("1.6"))

        # Second interval: >=2.0,<2.5
        assert specs[1].contains(Version("2.0"))
        assert specs[1].contains(Version("2.4"))
        assert not specs[1].contains(Version("2.5"))  # Exclusive (fixed)
