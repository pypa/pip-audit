"""Hypothesis strategies for pip-audit range types.

These strategies generate random but valid inputs for property-based testing:
- PEP 440 versions
- SpecifierSets with various constraint patterns
- Tuples of SpecifierSets for union semantics
"""

from __future__ import annotations

from hypothesis import strategies as st
from packaging.specifiers import SpecifierSet
from packaging.version import Version


@st.composite
def versions(
    draw: st.DrawFn,
    min_parts: int = 1,
    max_parts: int = 3,
    max_value: int = 20,
) -> Version:
    """Generate valid PEP 440 versions like 1.2.3.

    Args:
        min_parts: Minimum number of version components (default 1)
        max_parts: Maximum number of version components (default 3)
        max_value: Maximum value for each component (default 20)

    Returns:
        A packaging.version.Version object
    """
    parts = draw(st.integers(min_parts, max_parts))
    nums = [draw(st.integers(0, max_value)) for _ in range(parts)]
    return Version(".".join(str(n) for n in nums))


@st.composite
def version_lists(
    draw: st.DrawFn,
    min_size: int = 1,
    max_size: int = 30,
) -> list[Version]:
    """Generate sorted lists of unique versions.

    Returns versions sorted in ascending order, simulating
    the set of known versions from a package registry.

    Args:
        min_size: Minimum number of versions (default 1)
        max_size: Maximum number of versions (default 30)

    Returns:
        A sorted list of unique Version objects
    """
    vs = draw(
        st.lists(
            versions(),
            min_size=min_size,
            max_size=max_size,
            unique_by=str,  # Ensure unique version strings
        )
    )
    return sorted(vs)


@st.composite
def specifier_sets(
    draw: st.DrawFn,
    versions_pool: list[Version] | None = None,
) -> SpecifierSet:
    """Generate SpecifierSets from common patterns.

    If a versions_pool is provided, may use versions from it
    to create more relevant constraints.

    Patterns generated:
    - Single comparisons: >=1.0, <2.0, ==1.5, !=1.3
    - Bounded ranges: >=1.0,<2.0
    - Empty specifier (matches all)

    Args:
        versions_pool: Optional list of versions to sample from

    Returns:
        A SpecifierSet object
    """
    # Occasionally return empty specifier (matches all)
    if draw(st.integers(0, 10)) == 0:
        return SpecifierSet()

    if versions_pool and len(versions_pool) > 0 and draw(st.booleans()):
        # Use a version from the pool
        v = draw(st.sampled_from(versions_pool))
        op = draw(st.sampled_from([">=", ">", "<=", "<", "==", "!="]))
        return SpecifierSet(f"{op}{v}")
    else:
        # Generate from scratch
        v = draw(versions())
        op = draw(st.sampled_from([">=", ">", "<=", "<"]))

        # Optionally add upper bound for a range
        if draw(st.booleans()):
            v2 = draw(versions())
            if v2 > v:
                return SpecifierSet(f"{op}{v},<{v2}")

        return SpecifierSet(f"{op}{v}")


@st.composite
def affected_unions(
    draw: st.DrawFn,
    versions_pool: list[Version] | None = None,
    min_ranges: int = 1,
    max_ranges: int = 4,
) -> tuple[SpecifierSet, ...]:
    """Generate tuple of SpecifierSets (union semantics).

    A version is considered vulnerable if it matches ANY of the
    SpecifierSets in the tuple (union semantics).

    Args:
        versions_pool: Optional list of versions to sample from
        min_ranges: Minimum number of ranges in the union (default 1)
        max_ranges: Maximum number of ranges in the union (default 4)

    Returns:
        A tuple of SpecifierSet objects
    """
    n = draw(st.integers(min_ranges, max_ranges))
    specs = [draw(specifier_sets(versions_pool)) for _ in range(n)]
    return tuple(specs)


@st.composite
def constraint_tuples(
    draw: st.DrawFn,
    versions_pool: list[Version] | None = None,
    min_constraints: int = 0,
    max_constraints: int = 5,
) -> list[tuple[SpecifierSet, str]]:
    """Generate list of (SpecifierSet, source) constraint tuples.

    This matches the input format of compute_envelope().

    Args:
        versions_pool: Optional list of versions to sample from
        min_constraints: Minimum number of constraints (default 0)
        max_constraints: Maximum number of constraints (default 5)

    Returns:
        List of (SpecifierSet, source_string) tuples
    """
    n = draw(st.integers(min_constraints, max_constraints))
    return [
        (draw(specifier_sets(versions_pool)), f"source-{i}")
        for i in range(n)
    ]
