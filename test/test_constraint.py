"""Tests for constraint graph and envelope computation."""

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from pip_audit._constraint import (
    ConstraintGraph,
    PackageNode,
    compute_envelope,
    is_envelope_empty,
)


class TestComputeEnvelope:
    def test_empty_constraints(self):
        envelope = compute_envelope([])
        assert str(envelope) == ""  # Empty = all versions

    def test_single_constraint(self):
        constraints = [(SpecifierSet(">=1.0"), "pyproject.toml")]
        envelope = compute_envelope(constraints)
        assert str(envelope) == ">=1.0"

    def test_intersection(self):
        constraints = [
            (SpecifierSet(">=1.0"), "pyproject.toml"),
            (SpecifierSet("<2.0"), "requests from pyproject.toml"),
        ]
        envelope = compute_envelope(constraints)
        # Intersection should be >=1.0,<2.0
        assert envelope.contains("1.5")
        assert not envelope.contains("0.9")
        assert not envelope.contains("2.0")

    def test_narrowing(self):
        constraints = [
            (SpecifierSet(">=1.0"), "direct"),
            (SpecifierSet(">=1.5"), "transitive"),
        ]
        envelope = compute_envelope(constraints)
        # Should be >=1.5 (narrower)
        assert not envelope.contains("1.4")
        assert envelope.contains("1.5")


class TestPackageNode:
    def test_add_constraint_returns_change(self):
        node = PackageNode(name="foo", constraints=[])

        # First constraint - should change envelope
        changed = node.add_constraint(SpecifierSet(">=1.0"), "pyproject.toml")
        assert changed
        assert str(node.envelope) == ">=1.0"

        # Same constraint - should not change
        changed = node.add_constraint(SpecifierSet(">=1.0"), "other")
        assert not changed

    def test_add_narrowing_constraint(self):
        node = PackageNode(name="foo", constraints=[])
        node.add_constraint(SpecifierSet(">=1.0"), "direct")

        # Narrower constraint - should change
        changed = node.add_constraint(SpecifierSet("<2.0"), "transitive")
        assert changed
        assert node.envelope.contains("1.5")
        assert not node.envelope.contains("2.0")


class TestConstraintGraph:
    def test_get_or_create_new(self):
        graph = ConstraintGraph()
        node = graph.get_or_create("Foo")
        assert node.name == "foo"  # Canonicalized
        assert "foo" in graph.packages

    def test_get_or_create_existing(self):
        graph = ConstraintGraph()
        node1 = graph.get_or_create("foo")
        node1.add_constraint(SpecifierSet(">=1.0"), "test")

        node2 = graph.get_or_create("FOO")  # Different case
        assert node2 is node1
        assert len(node1.constraints) == 1


class TestUnpinnedDependencyTraversal:
    """Tests for P1 bug fix: unpinned dependencies should trigger BFS expansion."""

    def test_empty_specifier_first_constraint_returns_true(self):
        """First constraint should return True even if envelope is empty (unpinned dep)."""
        node = PackageNode(name="requests", constraints=[])

        # Empty specifier (unpinned dependency like "requests" with no version)
        changed = node.add_constraint(SpecifierSet(), "pyproject.toml")

        # Should return True because this is the FIRST constraint
        # This triggers BFS expansion to discover transitive dependencies
        assert changed is True
        assert str(node.envelope) == ""  # Envelope is still empty

    def test_second_empty_specifier_returns_false(self):
        """Second empty constraint should return False (no change)."""
        node = PackageNode(name="requests", constraints=[])

        # First empty constraint - should return True
        node.add_constraint(SpecifierSet(), "pyproject.toml")

        # Second empty constraint - should return False (no change)
        changed = node.add_constraint(SpecifierSet(), "other-source")
        assert changed is False

    def test_first_constraint_always_triggers_expansion(self):
        """Verify first constraint always returns True regardless of specifier content."""
        # Test with various specifier types
        test_cases = [
            SpecifierSet(),  # Empty
            SpecifierSet(">=1.0"),  # Lower bound
            SpecifierSet("==1.0"),  # Exact
        ]

        for spec in test_cases:
            node = PackageNode(name="pkg", constraints=[])
            changed = node.add_constraint(spec, "source")
            assert changed is True, f"First constraint {spec} should return True"


class TestIsEnvelopeEmpty:
    """Tests for P2b bug fix: is_envelope_empty returns None for unknown."""

    def test_returns_false_for_empty_specifier(self):
        """Empty specifier (all versions allowed) is never empty."""
        result = is_envelope_empty(SpecifierSet(), [])
        assert result is False

    def test_returns_none_for_empty_known_versions(self):
        """Unknown (None) when no versions to test against."""
        # Non-empty specifier but no known versions to check
        result = is_envelope_empty(SpecifierSet(">=1.0"), [])
        assert result is None

    def test_returns_false_when_versions_satisfy(self):
        """Returns False when at least one version satisfies."""
        envelope = SpecifierSet(">=1.0,<2.0")
        known_versions = [Version("0.9"), Version("1.0"), Version("1.5"), Version("2.0")]
        result = is_envelope_empty(envelope, known_versions)
        assert result is False

    def test_returns_true_when_no_versions_satisfy(self):
        """Returns True when no versions satisfy (confirmed unsatisfiable)."""
        envelope = SpecifierSet(">=2.0,<1.0")  # Impossible range
        known_versions = [Version("0.9"), Version("1.0"), Version("1.5"), Version("2.0")]
        result = is_envelope_empty(envelope, known_versions)
        assert result is True

    def test_distinguishes_unknown_from_unsatisfiable(self):
        """Critical: empty known_versions returns None, not True."""
        # This was the P2b bug - empty known_versions falsely triggered unsatisfiable
        envelope = SpecifierSet(">=1.0")  # Valid specifier
        result_empty = is_envelope_empty(envelope, [])
        result_with_versions = is_envelope_empty(envelope, [Version("1.5")])

        assert result_empty is None  # Unknown
        assert result_with_versions is False  # Satisfiable


class TestMultipleParentConstraints:
    """Tests for P1 bug fix: multiple parents constraining same package."""

    def test_two_direct_deps_same_transitive_different_constraints(self):
        """
        Regression test: two direct deps requiring same package with different specifiers.

        Before fix: second constraint was skipped (processed set used (pkg, depth) key),
        resulting in envelope that was too broad.

        After fix: both constraints are intersected correctly.
        """
        node = PackageNode(name="foo", constraints=[])

        # Simulate two direct deps both requiring foo:
        # - bar requires foo>=1.0
        # - baz requires foo<2.0
        # Both are at depth 0 (direct transitive deps)

        changed1 = node.add_constraint(SpecifierSet(">=1.0"), "bar from pyproject.toml")
        assert changed1 is True

        # This used to be skipped before the fix!
        changed2 = node.add_constraint(SpecifierSet("<2.0"), "baz from pyproject.toml")
        assert changed2 is True  # Envelope narrowed

        # Envelope should be intersection: >=1.0,<2.0
        assert node.envelope.contains(Version("1.0"))
        assert node.envelope.contains(Version("1.5"))
        assert not node.envelope.contains(Version("0.9"))  # Below lower bound
        assert not node.envelope.contains(Version("2.0"))  # At/above upper bound

    def test_three_constraints_all_applied(self):
        """Test that three constraints from different sources are all intersected."""
        node = PackageNode(name="requests", constraints=[])

        node.add_constraint(SpecifierSet(">=2.0"), "direct")
        node.add_constraint(SpecifierSet("<3.0"), "transitive-a")
        node.add_constraint(SpecifierSet("!=2.5.0"), "transitive-b")

        # All three constraints should be in effect
        assert node.envelope.contains(Version("2.0"))
        assert node.envelope.contains(Version("2.4"))
        assert not node.envelope.contains(Version("2.5.0"))  # Excluded
        assert node.envelope.contains(Version("2.6"))
        assert not node.envelope.contains(Version("3.0"))  # Above upper bound


class TestGraphWithMissingMetadata:
    """Tests for graph building when metadata is missing (is_envelope_empty returns None)."""

    def test_graph_proceeds_when_metadata_missing(self):
        """
        Verify build_constraint_graph proceeds when is_envelope_empty returns None.

        When a package has no known versions (metadata unavailable), is_envelope_empty
        returns None (unknown) rather than True (unsatisfiable). The graph builder
        should NOT add this to unsatisfiables and should proceed with traversal.
        """
        from unittest.mock import Mock

        from packaging.requirements import Requirement

        from pip_audit._constraint import build_constraint_graph

        # Create a mock metadata provider that returns empty versions
        mock_metadata = Mock()

        # For "test-pkg": has metadata but no versions match envelope
        test_pkg_meta = Mock()
        test_pkg_meta.all_versions = []  # No versions known
        test_pkg_meta.yanked_versions = set()

        def get_requires_dist(name, specifier, stats):
            # Return empty list - no dependencies
            return []

        mock_metadata.get_metadata.return_value = test_pkg_meta
        mock_metadata.get_requires_dist = get_requires_dist

        # Build graph with a single direct dependency
        direct_deps = [Requirement("test-pkg>=1.0")]
        graph, unsatisfiables, coverage = build_constraint_graph(
            direct_deps=direct_deps,
            metadata=mock_metadata,
        )

        # Verify graph was built
        assert "test-pkg" in graph.packages

        # Verify unsatisfiables is empty (missing metadata = unknown, not unsatisfiable)
        assert len(unsatisfiables) == 0

        # Verify the package has the correct envelope
        node = graph.packages["test-pkg"]
        assert node.envelope == SpecifierSet(">=1.0")

    def test_graph_continues_past_missing_metadata_for_transitive(self):
        """
        Verify graph building continues when a transitive dep has missing metadata.

        The graph should still include both direct and transitive deps,
        even if transitive has no version info.
        """
        from unittest.mock import Mock

        from packaging.requirements import Requirement

        from pip_audit._constraint import build_constraint_graph

        mock_metadata = Mock()

        # For "direct-pkg": has metadata with transitive dep
        direct_pkg_meta = Mock()
        direct_pkg_meta.all_versions = [Version("1.0"), Version("2.0")]
        direct_pkg_meta.yanked_versions = set()

        # For "transitive-pkg": no versions known
        transitive_pkg_meta = Mock()
        transitive_pkg_meta.all_versions = []
        transitive_pkg_meta.yanked_versions = set()

        def get_metadata(name):
            if name == "direct-pkg":
                return direct_pkg_meta
            return transitive_pkg_meta

        def get_requires_dist(name, specifier, stats):
            if name == "direct-pkg":
                stats.versions_examined += 1
                stats.versions_with_requires_dist += 1
                return [Requirement("transitive-pkg>=0.1")]
            return []

        mock_metadata.get_metadata = get_metadata
        mock_metadata.get_requires_dist = get_requires_dist

        direct_deps = [Requirement("direct-pkg>=1.0")]
        graph, unsatisfiables, coverage = build_constraint_graph(
            direct_deps=direct_deps,
            metadata=mock_metadata,
        )

        # Both packages should be in graph
        assert "direct-pkg" in graph.packages
        assert "transitive-pkg" in graph.packages

        # No unsatisfiables (missing metadata != unsatisfiable)
        assert len(unsatisfiables) == 0
