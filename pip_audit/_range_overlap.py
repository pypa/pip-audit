"""
Range overlap detection for constraint envelope analysis.

This module determines whether an allowed version range overlaps
with a vulnerability's affected version range.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from packaging.specifiers import SpecifierSet
from packaging.version import Version

# Type alias for range key: tuple of (lower_bound, upper_bound) intervals
# None means unbounded (-∞ for lower, +∞ for upper)
RangeKey = tuple[tuple[Version | None, Version | None], ...]

# Patterns for "zero" versions that should be treated as -∞
_ZERO_VERSION_PATTERNS = re.compile(r"^0(\.0)*$")

if TYPE_CHECKING:
    from pip_audit._range_types import AffectedUnion, AllowedEnvelope


def ranges_overlap(
    allowed: "AllowedEnvelope | SpecifierSet",
    vulnerable_ranges: "AffectedUnion | tuple[SpecifierSet, ...] | SpecifierSet",
    known_versions: list[Version],
    yanked_versions: set[Version] | None = None,
    include_prereleases: bool = False,
) -> tuple[bool, list[Version]]:
    """
    Check if allowed and vulnerable ranges overlap.

    Uses known_versions (from PyPI) to test membership in both sets.
    This is a pragmatic approach that's complete for released versions
    and avoids complex interval arithmetic.

    Args:
        allowed: The constraint envelope (versions the user permits)
        vulnerable_ranges: The vulnerability's affected ranges (union semantics).
            Can be a tuple of SpecifierSets (version matches if in ANY range)
            or a single SpecifierSet for backwards compatibility.
        known_versions: All known versions for the package (from PyPI)
        yanked_versions: Versions that have been yanked (excluded by default)
        include_prereleases: Whether to include prereleases (default: False,
            unless allowed specifier explicitly admits them)

    Returns:
        Tuple of (overlaps: bool, overlapping_versions: list[Version])
        - overlaps: True if any version is in both ranges
        - overlapping_versions: The specific versions that are vulnerable
          AND permitted by constraints

    Version filtering defaults:
    - Yanked releases: excluded (if yanked_versions provided)
    - Prereleases: excluded unless include_prereleases=True OR
      the allowed specifier explicitly admits them (e.g., >=1.0.0a1)

    Note:
        Correctness invariants (e.g., result is subset of known_versions) are
        verified via Hypothesis property tests in test/test_properties.py and
        formal verification with CrossHair in test/model_verification.py.
    """
    if yanked_versions is None:
        yanked_versions = set()

    # Normalize vulnerable_ranges to tuple
    if isinstance(vulnerable_ranges, SpecifierSet):
        vulnerable_ranges = (vulnerable_ranges,)

    # Determine if we should include prereleases
    # SpecifierSet.prereleases is True if any specifier explicitly includes them
    should_include_prereleases = include_prereleases or bool(allowed.prereleases)

    def should_include(v: Version) -> bool:
        """Filter function for versions to consider."""
        # Exclude yanked versions
        if v in yanked_versions:
            return False

        # Handle prereleases
        if v.is_prerelease and not should_include_prereleases:
            return False

        return True

    def is_vulnerable(v: Version) -> bool:
        """Check if version matches ANY of the vulnerable ranges (union)."""
        for vuln_range in vulnerable_ranges:
            if vuln_range.contains(v, prereleases=should_include_prereleases):
                return True
        return False

    # Find versions that are:
    # 1. Not filtered out (not yanked, prereleases handled)
    # 2. In the allowed range
    # 3. In ANY of the vulnerable ranges (union semantics)
    overlapping: list[Version] = []

    for v in known_versions:
        if not should_include(v):
            continue

        # Check if version is in both ranges
        in_allowed = allowed.contains(v, prereleases=should_include_prereleases)

        if in_allowed and is_vulnerable(v):
            overlapping.append(v)

    # Sort for consistent output
    overlapping.sort()

    return bool(overlapping), overlapping


def specifier_from_osv_range(events: list[dict]) -> tuple[SpecifierSet, ...]:
    """
    Convert OSV range events to tuple of SpecifierSets (one per interval).

    OSV uses a list of events with "introduced" and "fixed" keys
    to describe affected version ranges. A single range entry can contain
    MULTIPLE disjoint intervals (e.g., versions 1.0-1.5 OR 2.0-2.5).

    INPUT:
        events: List of event dicts from ONE OSV affected[].ranges[].events[]
            Example: [{"introduced": "1.0"}, {"fixed": "1.5"}]

    OUTPUT:
        Tuple of SpecifierSets, one per interval. Union semantics apply:
        a version is vulnerable if it matches ANY of the returned SpecifierSets.

    SEMANTIC:
        Each interval is INDEPENDENT. The caller should treat the tuple
        as a union (version is vulnerable if in ANY range).

    Examples:
        [] -> ()
        [{"introduced": "0"}, {"fixed": "1.5"}] -> (SpecifierSet("<1.5"),)
        [{"introduced": "1.0"}, {"fixed": "1.5"}] -> (SpecifierSet(">=1.0,<1.5"),)
        [{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"fixed": "2.5"}]
            -> (SpecifierSet(">=1.0,<1.5"), SpecifierSet(">=2.0,<2.5"))
        [{"introduced": "0"}] -> (SpecifierSet(),)  # Empty = matches all
    """
    if not events:
        return ()

    # Build individual spec strings, one per interval
    specs: list[str] = []
    current_introduced: str | None = None

    for event in events:
        if "introduced" in event:
            # Only set if not already in an open interval (OSV spec: once introduced,
            # versions stay affected until a fixed event closes the interval)
            if current_introduced is None:
                introduced = event["introduced"]
                # "0" means "all versions from the beginning"
                if introduced == "0":
                    current_introduced = "0"
                else:
                    current_introduced = introduced
        elif "fixed" in event and current_introduced is not None:
            fixed = event["fixed"]
            if current_introduced == "0":
                specs.append(f"<{fixed}")
            else:
                specs.append(f">={current_introduced},<{fixed}")
            current_introduced = None
        elif "last_affected" in event and current_introduced is not None:
            # last_affected is inclusive (version X and earlier are affected)
            last = event["last_affected"]
            if current_introduced == "0":
                specs.append(f"<={last}")
            else:
                specs.append(f">={current_introduced},<={last}")
            current_introduced = None

    # Handle open range (introduced but no fixed)
    if current_introduced is not None:
        if current_introduced == "0":
            # All versions are affected (no fix) - empty SpecifierSet matches everything
            return (SpecifierSet(),)
        else:
            specs.append(f">={current_introduced}")

    # Return tuple of SpecifierSets (one per interval, union semantics)
    if specs:
        return tuple(SpecifierSet(s) for s in specs)
    else:
        return ()


def _is_zero_version(version_str: str) -> bool:
    """Check if a version string represents 'zero' (i.e., -∞ for practical purposes)."""
    return bool(_ZERO_VERSION_PATTERNS.match(version_str))


def compute_range_key(events: list[dict]) -> RangeKey:
    """
    Compute a normalized range key from OSV events for grouping.

    This converts OSV range events to a canonical tuple of intervals
    for use as a grouping key. The normalization:
    - Treats >=0 / >=0.0 / etc. as unbounded lower (-∞)
    - Represents intervals as (lower, upper) tuples with None for unbounded
    - Supports disjoint ranges (unions) as multiple intervals

    Args:
        events: List of event dicts from OSV affected[].ranges[].events[]
            Example: [{"introduced": "1.0"}, {"fixed": "1.5"}]

    Returns:
        Tuple of (lower_bound, upper_bound) intervals, sorted and merged.
        None represents unbounded (-∞ for lower, +∞ for upper).

    Examples:
        [{"introduced": "0"}, {"fixed": "3.7"}] -> ((None, Version("3.7")),)
        [{"introduced": "1.0"}, {"fixed": "1.5"}] -> ((Version("1.0"), Version("1.5")),)
        [{"introduced": "1.0"}] -> ((Version("1.0"), None),)
    """
    if not events:
        return ()

    intervals: list[tuple[Version | None, Version | None]] = []
    current_introduced: str | None = None

    for event in events:
        if "introduced" in event:
            current_introduced = event["introduced"]
        elif "fixed" in event and current_introduced is not None:
            fixed = event["fixed"]
            # Normalize: >=0 treated as unbounded lower
            lower = None if _is_zero_version(current_introduced) else Version(current_introduced)
            upper = Version(fixed)
            intervals.append((lower, upper))
            current_introduced = None

    # Handle open range (introduced but no fixed)
    if current_introduced is not None:
        lower = None if _is_zero_version(current_introduced) else Version(current_introduced)
        intervals.append((lower, None))

    # Sort intervals by lower bound (None sorts first)
    def sort_key(
        interval: tuple[Version | None, Version | None],
    ) -> tuple[int, Version | None]:
        lower: Version | None = interval[0]
        # None (unbounded) sorts first
        if lower is None:
            return (0, None)
        return (1, lower)

    intervals.sort(key=sort_key)

    # Merge overlapping/adjacent intervals
    merged: list[tuple[Version | None, Version | None]] = []
    for interval in intervals:
        curr_lower: Version | None = interval[0]
        curr_upper: Version | None = interval[1]
        if not merged:
            merged.append((curr_lower, curr_upper))
            continue

        prev_lower, prev_upper = merged[-1]

        # Check if intervals can be merged
        # They can merge if prev_upper >= curr_lower (or either is unbounded)
        can_merge = False
        if prev_upper is None:
            # Previous interval extends to infinity, absorbs current
            can_merge = True
        elif curr_lower is None:
            # Current starts at -∞, should have been first
            can_merge = True
        elif prev_upper >= curr_lower:
            # Overlapping or adjacent
            can_merge = True

        if can_merge:
            # Merge: take min lower and max upper
            new_lower: Version | None
            new_upper: Version | None
            if prev_lower is None or curr_lower is None:
                new_lower = None
            else:
                new_lower = min(prev_lower, curr_lower)
            if prev_upper is None or curr_upper is None:
                new_upper = None
            else:
                new_upper = max(prev_upper, curr_upper)
            merged[-1] = (new_lower, new_upper)
        else:
            merged.append((curr_lower, curr_upper))

    return tuple(merged)
