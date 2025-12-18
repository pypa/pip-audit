"""Property-based tests for formal verification.

This module uses Hypothesis to generate thousands of random test cases
and verify that:
1. Production code matches oracle (reference) implementations
2. Mathematical invariants (metamorphic properties) hold

Test classes:
- TestOverlapOracleEquivalence: ranges_overlap matches oracle
- TestOverlapMetamorphicProperties: overlap invariants
- TestEnvelopeOracleEquivalence: compute_envelope matches oracle
- TestEnvelopeMetamorphicProperties: envelope invariants
"""

from __future__ import annotations

import random

import hypothesis.strategies as st
from hypothesis import HealthCheck, assume, given, settings
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from pip_audit._constraint import compute_envelope
from pip_audit._range_overlap import ranges_overlap

from .oracle import oracle_envelope, oracle_envelope_contains, oracle_overlap
from .strategies import affected_unions, specifier_sets, version_lists


class TestOverlapOracleEquivalence:
    """Test that ranges_overlap matches oracle."""

    @given(st.data())
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    def test_ranges_overlap_matches_oracle(self, data: st.DataObject) -> None:
        """Production ranges_overlap equals oracle on all generated inputs."""
        known_versions = data.draw(version_lists(min_size=5, max_size=30))
        allowed = data.draw(specifier_sets(known_versions))
        affected = data.draw(affected_unions(known_versions, min_ranges=1, max_ranges=3))

        oracle_result = oracle_overlap(allowed, affected, known_versions)

        overlaps, prod_versions = ranges_overlap(
            allowed, affected, known_versions, include_prereleases=True
        )
        prod_result = set(prod_versions)

        assert prod_result == oracle_result, (
            f"Mismatch!\n"
            f"  allowed={allowed}\n"
            f"  affected={affected}\n"
            f"  known={known_versions}\n"
            f"  oracle={oracle_result}\n"
            f"  production={prod_result}"
        )

    @given(st.data())
    @settings(max_examples=200)
    def test_overlap_with_empty_allowed(self, data: st.DataObject) -> None:
        """Empty allowed specifier should match all vulnerable versions."""
        known_versions = data.draw(version_lists(min_size=5, max_size=20))
        affected = data.draw(affected_unions(known_versions, min_ranges=1, max_ranges=2))

        # Empty allowed = matches all
        allowed = SpecifierSet()

        oracle_result = oracle_overlap(allowed, affected, known_versions)
        _, prod_versions = ranges_overlap(
            allowed, affected, known_versions, include_prereleases=True
        )

        assert set(prod_versions) == oracle_result


class TestOverlapMetamorphicProperties:
    """Test mathematical invariants for overlap (metamorphic testing)."""

    @given(st.data())
    @settings(max_examples=200)
    def test_overlap_subset_of_known(self, data: st.DataObject) -> None:
        """Overlap result is always a subset of known_versions."""
        known_versions = data.draw(version_lists())
        allowed = data.draw(specifier_sets(known_versions))
        affected = data.draw(affected_unions(known_versions))

        _, overlap = ranges_overlap(allowed, affected, known_versions)

        for v in overlap:
            assert v in known_versions, f"{v} not in known_versions"

    @given(st.data())
    @settings(max_examples=200)
    def test_overlap_satisfies_allowed(self, data: st.DataObject) -> None:
        """Every overlapping version satisfies allowed constraint."""
        known_versions = data.draw(version_lists())
        allowed = data.draw(specifier_sets(known_versions))
        affected = data.draw(affected_unions(known_versions))

        _, overlap = ranges_overlap(allowed, affected, known_versions, include_prereleases=True)

        for v in overlap:
            # Empty specifier matches everything
            if str(allowed):
                assert allowed.contains(v, prereleases=True), f"{v} not in {allowed}"

    @given(st.data())
    @settings(max_examples=200)
    def test_overlap_in_vulnerable(self, data: st.DataObject) -> None:
        """Every overlapping version is in at least one affected range."""
        known_versions = data.draw(version_lists())
        allowed = data.draw(specifier_sets(known_versions))
        affected = data.draw(affected_unions(known_versions))

        _, overlap = ranges_overlap(allowed, affected, known_versions, include_prereleases=True)

        for v in overlap:
            in_any = any(
                (not str(spec) or spec.contains(v, prereleases=True))
                for spec in affected
            )
            assert in_any, f"{v} not in any of {affected}"

    @given(st.data())
    @settings(max_examples=200)
    def test_add_affected_range_monotonic(self, data: st.DataObject) -> None:
        """Adding to affected_union can only increase or maintain overlap."""
        known_versions = data.draw(version_lists())
        allowed = data.draw(specifier_sets(known_versions))
        affected1 = data.draw(affected_unions(known_versions, min_ranges=1, max_ranges=2))
        extra_range = data.draw(specifier_sets(known_versions))
        affected2 = affected1 + (extra_range,)

        _, overlap1 = ranges_overlap(allowed, affected1, known_versions, include_prereleases=True)
        _, overlap2 = ranges_overlap(allowed, affected2, known_versions, include_prereleases=True)

        # Adding a range can only increase overlap (union semantics)
        assert set(overlap1) <= set(overlap2), (
            f"Monotonicity violated!\n"
            f"  overlap with {affected1}: {overlap1}\n"
            f"  overlap with {affected2}: {overlap2}"
        )


class TestEnvelopeOracleEquivalence:
    """Test that compute_envelope matches oracle."""

    @given(st.data())
    @settings(max_examples=500)
    def test_envelope_matches_oracle(self, data: st.DataObject) -> None:
        """Production compute_envelope equals oracle on all generated inputs."""
        known_versions = data.draw(version_lists(min_size=5, max_size=30))
        n_constraints = data.draw(st.integers(0, 5))
        constraints = [
            (data.draw(specifier_sets(known_versions)), f"source-{i}")
            for i in range(n_constraints)
        ]

        # Oracle: just the specifiers
        specs_only = [c[0] for c in constraints]
        oracle_env = oracle_envelope(specs_only)

        # Production
        prod_env = compute_envelope(constraints)

        # Compare by evaluating membership on all known versions
        for v in known_versions:
            oracle_in = oracle_env.contains(v, prereleases=True) if str(oracle_env) else True
            prod_in = prod_env.contains(v, prereleases=True) if str(prod_env) else True
            assert oracle_in == prod_in, (
                f"Envelope membership mismatch for {v}!\n"
                f"  constraints={[str(c[0]) for c in constraints]}\n"
                f"  oracle={oracle_env} ({oracle_in})\n"
                f"  production={prod_env} ({prod_in})"
            )

    @given(st.data())
    @settings(max_examples=200)
    def test_envelope_empty_constraints(self, data: st.DataObject) -> None:
        """Empty constraints should produce envelope that matches everything."""
        known_versions = data.draw(version_lists(min_size=5, max_size=20))

        prod_env = compute_envelope([])

        # Empty envelope matches all
        for v in known_versions:
            if str(prod_env):
                in_env = prod_env.contains(v, prereleases=True)
            else:
                in_env = True
            assert in_env, f"{v} should be in empty envelope"


class TestEnvelopeMetamorphicProperties:
    """Test mathematical invariants for envelope computation."""

    @given(st.data())
    @settings(max_examples=200)
    def test_envelope_monotone_narrowing(self, data: st.DataObject) -> None:
        """Adding a constraint can only narrow (never widen) the envelope."""
        known_versions = data.draw(version_lists(min_size=10, max_size=30))
        n = data.draw(st.integers(1, 3))
        constraints1 = [
            (data.draw(specifier_sets(known_versions)), f"source-{i}")
            for i in range(n)
        ]
        extra = (data.draw(specifier_sets(known_versions)), "extra")
        constraints2 = constraints1 + [extra]

        env1 = compute_envelope(constraints1)
        env2 = compute_envelope(constraints2)

        # Every version in env2 must also be in env1 (narrowing)
        for v in known_versions:
            in_env1 = env1.contains(v, prereleases=True) if str(env1) else True
            in_env2 = env2.contains(v, prereleases=True) if str(env2) else True
            if in_env2:
                assert in_env1, (
                    f"Monotonicity violated! {v} in env2 but not env1\n"
                    f"  constraints1={[str(c[0]) for c in constraints1]}\n"
                    f"  constraints2={[str(c[0]) for c in constraints2]}\n"
                    f"  env1={env1}\n"
                    f"  env2={env2}"
                )

    @given(st.data())
    @settings(max_examples=200)
    def test_envelope_order_independent(self, data: st.DataObject) -> None:
        """Envelope is independent of constraint application order."""
        known_versions = data.draw(version_lists(min_size=5, max_size=20))
        n = data.draw(st.integers(2, 4))
        constraints = [
            (data.draw(specifier_sets(known_versions)), f"source-{i}")
            for i in range(n)
        ]

        # Shuffle order
        shuffled = constraints.copy()
        random.shuffle(shuffled)

        env_original = compute_envelope(constraints)
        env_shuffled = compute_envelope(shuffled)

        # Must produce equivalent envelopes (same membership)
        for v in known_versions:
            in_orig = env_original.contains(v, prereleases=True) if str(env_original) else True
            in_shuf = env_shuffled.contains(v, prereleases=True) if str(env_shuffled) else True
            assert in_orig == in_shuf, (
                f"Order dependence! {v} differs\n"
                f"  original order: {[str(c[0]) for c in constraints]} -> {env_original}\n"
                f"  shuffled order: {[str(c[0]) for c in shuffled]} -> {env_shuffled}"
            )

    @given(st.data())
    @settings(max_examples=200)
    def test_conflicting_constraints_empty_envelope(self, data: st.DataObject) -> None:
        """Conflicting constraints produce an empty envelope (no versions match)."""
        known_versions = data.draw(version_lists(min_size=5, max_size=20))
        assume(len(known_versions) >= 2)

        # Pick a version and create conflicting constraints
        v = data.draw(st.sampled_from(known_versions))
        # >=v+1 and <v creates conflict
        idx = known_versions.index(v)
        if idx < len(known_versions) - 1:
            higher = known_versions[idx + 1]
            constraints = [
                (SpecifierSet(f">={higher}"), "source-1"),
                (SpecifierSet(f"<{v}"), "source-2"),
            ]

            env = compute_envelope(constraints)

            # No version should satisfy both constraints
            for ver in known_versions:
                in_env = env.contains(ver, prereleases=True) if str(env) else True
                if in_env:
                    # If envelope claims to contain ver, verify it's actually valid
                    in_c1 = constraints[0][0].contains(ver, prereleases=True)
                    in_c2 = constraints[1][0].contains(ver, prereleases=True)
                    assert in_c1 and in_c2, (
                        f"{ver} in envelope but doesn't satisfy all constraints\n"
                        f"  constraints={[str(c[0]) for c in constraints]}\n"
                        f"  env={env}"
                    )

    @given(st.data())
    @settings(max_examples=200)
    def test_envelope_membership_matches_direct_check(self, data: st.DataObject) -> None:
        """Envelope membership equals direct constraint checking."""
        known_versions = data.draw(version_lists(min_size=5, max_size=20))
        n = data.draw(st.integers(1, 4))
        constraints = [
            (data.draw(specifier_sets(known_versions)), f"source-{i}")
            for i in range(n)
        ]

        env = compute_envelope(constraints)
        specs_only = [c[0] for c in constraints]

        for v in known_versions:
            # Direct check: version must satisfy ALL constraints
            direct_in = oracle_envelope_contains(specs_only, v)

            # Envelope check
            env_in = env.contains(v, prereleases=True) if str(env) else True

            assert direct_in == env_in, (
                f"Membership mismatch for {v}!\n"
                f"  direct={direct_in}, envelope={env_in}\n"
                f"  constraints={[str(s) for s in specs_only]}\n"
                f"  envelope={env}"
            )
