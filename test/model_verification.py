"""
Reduced model for CrossHair verification.

This module provides abstract versions of the core algorithms using
simple types (integers) that CrossHair can symbolically execute.

The key insight: Version is a totally ordered set. We model it as int.
SpecifierSet is a predicate "contains(v) -> bool". We model it as a
pair of bounds (lower, upper) where None means unbounded.

If CrossHair proves the model correct, and our implementation follows
the same logic, we have high confidence in correctness.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import icontract


# --- Abstract Types ---


@dataclass(frozen=True)
class Range:
    """
    A version range modeled as [lower, upper).

    None means unbounded:
    - lower=None: from -infinity
    - upper=None: to +infinity
    """

    lower: int | None = None
    upper: int | None = None

    def contains(self, v: int) -> bool:
        """Check if version v is in this range."""
        if self.lower is not None and v < self.lower:
            return False
        if self.upper is not None and v >= self.upper:
            return False
        return True


# --- Model Functions ---


@icontract.ensure(
    lambda result, allowed, vulnerable_union, known_versions: all(
        v in known_versions for v in result
    ),
    "overlap ⊆ known_versions",
)
@icontract.ensure(
    lambda result, allowed, vulnerable_union, known_versions: all(
        allowed.contains(v) for v in result
    ),
    "overlap ⊆ allowed",
)
@icontract.ensure(
    lambda result, allowed, vulnerable_union, known_versions: all(
        any(r.contains(v) for r in vulnerable_union) for v in result
    ),
    "overlap ⊆ vulnerable_union",
)
def model_overlap(
    allowed: Range,
    vulnerable_union: tuple[Range, ...],
    known_versions: list[int],
) -> list[int]:
    """
    Model of ranges_overlap using abstract types.

    Mathematical definition:
        OVERLAP(allowed, vulnerable_union, known_versions) =
            { v ∈ known_versions | v ∈ allowed ∧ v ∈ ⋃(vulnerable_union) }

    Args:
        allowed: The constraint envelope (versions permitted)
        vulnerable_union: Tuple of affected ranges (union semantics)
        known_versions: All known versions

    Returns:
        List of versions in both allowed and vulnerable ranges
    """
    result: list[int] = []

    for v in known_versions:
        # Check if in allowed range
        if not allowed.contains(v):
            continue

        # Check if in any vulnerable range (union semantics)
        in_vulnerable = any(r.contains(v) for r in vulnerable_union)
        if not in_vulnerable:
            continue

        result.append(v)

    return result


@icontract.ensure(
    lambda result, ranges: (
        # If result has a lower bound, it must be >= all input lower bounds
        result.lower is None
        or all(r.lower is None or result.lower >= r.lower for r in ranges)
    ),
    "envelope.lower >= max(ranges.lower) - intersection tightens lower bound",
)
@icontract.ensure(
    lambda result, ranges: (
        # If result has an upper bound, it must be <= all input upper bounds
        result.upper is None
        or all(r.upper is None or result.upper <= r.upper for r in ranges)
    ),
    "envelope.upper <= min(ranges.upper) - intersection tightens upper bound",
)
def model_envelope(ranges: list[Range]) -> Range:
    """
    Model of compute_envelope using abstract types.

    Computes intersection of ranges.
    A version is in the envelope iff it's in ALL input ranges.

    Args:
        ranges: List of ranges to intersect

    Returns:
        The intersection range
    """
    if not ranges:
        return Range()  # Unbounded = all versions

    # Start with first range
    lower: int | None = None
    upper: int | None = None

    for r in ranges:
        # Intersect lower bounds: take the max
        if r.lower is not None:
            if lower is None:
                lower = r.lower
            else:
                lower = max(lower, r.lower)

        # Intersect upper bounds: take the min
        if r.upper is not None:
            if upper is None:
                upper = r.upper
            else:
                upper = min(upper, r.upper)

    return Range(lower=lower, upper=upper)


# --- Monotonicity Properties ---


@icontract.require(lambda ranges1, ranges2: len(ranges1) <= len(ranges2))
@icontract.require(lambda ranges1, ranges2: all(r in ranges2 for r in ranges1))
@icontract.ensure(
    lambda result: result,
    "adding constraints can only narrow (never widen) the envelope",
)
def model_envelope_monotone(ranges1: list[Range], ranges2: list[Range], test_v: int) -> bool:
    """
    Verify monotonicity: if ranges1 ⊆ ranges2, then envelope(ranges2) ⊆ envelope(ranges1).

    Adding more constraints can only narrow the envelope.
    """
    env1 = model_envelope(ranges1)
    env2 = model_envelope(ranges2)

    # If v is in env2, it must be in env1
    if env2.contains(test_v):
        return env1.contains(test_v)
    return True


def model_overlap_monotone(
    allowed: Range,
    vulnerable1: tuple[Range, ...],
    vulnerable2: tuple[Range, ...],
    known_versions: list[int],
) -> bool:
    """
    Verify monotonicity: if vulnerable1 ⊆ vulnerable2, overlap can only grow.

    Adding more vulnerable ranges increases the overlap.
    This is a property we test, not a function with contracts.
    """
    # Precondition: vulnerable1 is subset of vulnerable2
    if not all(r in vulnerable2 for r in vulnerable1):
        return True  # Precondition not met, vacuously true

    # Compute overlaps without going through decorated function
    overlap1: set[int] = set()
    overlap2: set[int] = set()

    for v in known_versions:
        if not allowed.contains(v):
            continue
        if any(r.contains(v) for r in vulnerable1):
            overlap1.add(v)
        if any(r.contains(v) for r in vulnerable2):
            overlap2.add(v)

    return overlap1 <= overlap2


# --- Test harness for CrossHair ---


def verify_overlap_correctness(
    allowed_lower: int | None,
    allowed_upper: int | None,
    vuln_lower: int | None,
    vuln_upper: int | None,
    v1: int,
    v2: int,
    v3: int,
) -> bool:
    """
    Entry point for CrossHair to verify overlap correctness.

    Uses small fixed-size inputs to make symbolic execution tractable.
    """
    allowed = Range(allowed_lower, allowed_upper)
    vulnerable = (Range(vuln_lower, vuln_upper),)
    known = [v1, v2, v3]

    result = model_overlap(allowed, vulnerable, known)

    # Postconditions are checked by icontract decorators
    # This function just needs to return without contract violation
    return True


def verify_envelope_correctness(
    r1_lower: int | None,
    r1_upper: int | None,
    r2_lower: int | None,
    r2_upper: int | None,
) -> bool:
    """
    Entry point for CrossHair to verify envelope correctness.
    """
    ranges = [Range(r1_lower, r1_upper), Range(r2_lower, r2_upper)]
    result = model_envelope(ranges)

    # Postconditions are checked by icontract decorators
    return True
