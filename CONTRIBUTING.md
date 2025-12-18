# Contributing to pip-audit-range

Thank you for your interest in contributing to pip-audit-range.

This repository is a fork of pip-audit, but it is maintained independently and has a narrow, explicit scope: development and refinement of Range Mode (constraint range analysis). Contributions outside that scope are intentionally limited.

---

## Scope of contributions

This project accepts contributions that relate directly to Range Mode, including:

- Constraint range analysis semantics
- Transitive constraint graph construction
- Vulnerability range handling and normalization
- Output formatting for Range Mode findings
- Correctness testing (property-based tests, oracle tests, model verification)
- Performance, caching, or observability improvements specific to Range Mode

Changes to the original environment-based auditing behavior inherited from upstream pip-audit are out of scope for this repository.

If your change would affect non-range audit behavior, it likely belongs upstream instead of here.

---

## Relationship to upstream

This repository tracks upstream pip-audit to minimize divergence, but:

- This project does not accept contributions aimed at changing upstream behavior
- This project does not enforce upstream contribution guidelines
- This project does not require contributors to coordinate with upstream maintainers

Design choices in this fork may intentionally differ from upstream to support Range Mode semantics.

---

## Development philosophy

Range Mode is built around explicit semantics and defensible correctness claims. Contributions should:

- Preserve the distinction between intersection (allowed versions) and union (affected versions)
- Avoid conflating environment resolution with constraint analysis
- Include tests that exercise edge cases and invariants
- Prefer clarity and correctness over premature optimization

Where feasible, contributors are encouraged to:

- Add or update property-based tests
- Extend oracle-based equivalence checks
- Add model-level tests for new logic

---

## Testing requirements

All contributions must pass the existing test suite.

For changes affecting Range Mode semantics, contributors are encouraged (but not strictly required) to:

- Add property-based tests covering the new behavior
- Update oracle or model tests if semantics change

Symbolic verification (e.g. CrossHair) is not required for every contribution, but changes should not invalidate existing verification assumptions.

---

## Style and tooling

This project follows standard Python tooling and style:

- Python 3.x
- pytest for testing
- hypothesis for property-based tests
- mypy (strict mode) for static type checking

Code should prioritize readability and explicitness, particularly where semantics matter.

---

## What this project does not promise

To avoid confusion, contributions should not assume or imply that Range Mode:

- Predicts which versions will be installed
- Guarantees exploitability or safety
- Accounts for all future ecosystem changes
- Replaces environment-based auditing

Changes that introduce such claims will be asked to revise scope or documentation.

---

## Getting started

1. Fork the repository
2. Create a feature branch
3. Make focused changes within the scope described above
4. Ensure tests pass
5. Open a pull request with a clear description of the change and its rationale

Small, well-scoped changes with strong tests are preferred over large, cross-cutting refactors.
