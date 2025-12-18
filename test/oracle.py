"""Reference implementation for formal verification.

These functions are written to be OBVIOUSLY CORRECT, not fast.
They define ground truth for property-based testing.

The oracle implementations use the simplest possible logic:
enumerate all versions and check membership directly.
"""

from __future__ import annotations

from packaging.specifiers import SpecifierSet
from packaging.version import Version


def oracle_overlap(
    allowed: SpecifierSet,
    affected_union: tuple[SpecifierSet, ...],
    known_versions: list[Version],
    include_prereleases: bool = True,
) -> set[Version]:
    """
    Obviously correct overlap detection.

    Mathematical definition:
        OVERLAP(allowed, affected_union, known_versions) =
            { v in known_versions | v in allowed AND v in Union(affected_union) }

    Returns: set of versions that are BOTH:
    - Permitted by `allowed` (membership in intersection)
    - Vulnerable (membership in ANY of affected_union)

    This is the ground truth for testing ranges_overlap().
    """
    result: set[Version] = set()

    for v in known_versions:
        # Check if version is in allowed range
        # Empty SpecifierSet matches everything
        if str(allowed):
            in_allowed = allowed.contains(v, prereleases=include_prereleases)
        else:
            in_allowed = True

        # Check if version is in ANY of the affected ranges (union semantics)
        in_vulnerable = False
        for spec in affected_union:
            if str(spec):
                if spec.contains(v, prereleases=include_prereleases):
                    in_vulnerable = True
                    break
            else:
                # Empty SpecifierSet matches everything
                in_vulnerable = True
                break

        if in_allowed and in_vulnerable:
            result.add(v)

    return result


def oracle_envelope(constraints: list[SpecifierSet]) -> SpecifierSet:
    """
    Obviously correct envelope computation.

    Mathematical definition:
        ENVELOPE(constraints) = Intersection(constraints)
        A version is in the envelope iff it satisfies ALL constraints.

    Envelope = intersection of all constraints.
    In PEP 440, comma-joining specifier strings produces intersection.

    This is the ground truth for testing compute_envelope().
    """
    if not constraints:
        return SpecifierSet()  # Empty = all versions

    # Build combined specifier by joining all constraint strings
    all_specs: list[str] = []
    for spec in constraints:
        spec_str = str(spec)
        if spec_str:
            all_specs.append(spec_str)

    if not all_specs:
        return SpecifierSet()

    return SpecifierSet(",".join(all_specs))


def oracle_envelope_contains(
    constraints: list[SpecifierSet],
    version: Version,
    include_prereleases: bool = True,
) -> bool:
    """
    Check if a version is contained in the envelope of constraints.

    A version is in the envelope iff it satisfies ALL constraints.
    This is an alternative oracle that checks membership directly
    without constructing the combined SpecifierSet.
    """
    for spec in constraints:
        if str(spec):
            if not spec.contains(version, prereleases=include_prereleases):
                return False
        # Empty spec matches everything, continue
    return True
