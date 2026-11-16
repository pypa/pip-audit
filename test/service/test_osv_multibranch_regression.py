"""Offline regression tests for pip-audit 2.10.1 OSV fix-version aggregation.

Run inside a pip-audit v2.10.1 checkout after installing pip-audit[test].
Public test data is synthetic. No OSV calls, secrets or package exploit payloads.
These tests intentionally fail before the candidate patch and pass after it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from packaging.version import Version

import pip_audit._service as service


def affected(package: str, ecosystem: str, ranges: list[dict]) -> dict:
    return {
        "package": {"name": package, "ecosystem": ecosystem},
        "ranges": ranges,
    }


def ecosystem(introduced: str, fixed: str | None) -> dict:
    events = [{"introduced": introduced}]
    if fixed is not None:
        events.append({"fixed": fixed})
    return {"type": "ECOSYSTEM", "events": events}


def parsed_fixes(
    monkeypatch: pytest.MonkeyPatch, package: str, entries: list[dict]
) -> list[Version]:
    payload = {
        "vulns": [
            {
                "id": "GHSA-7xgj-8392-5q4r",
                "summary": "Synthetic regression case: retain both fixed branches",
                "schema_version": "1.9.0",
                "affected": entries,
            }
        ]
    }
    response = SimpleNamespace(raise_for_status=lambda: None, json=lambda: payload)
    osv = service.OsvService()
    monkeypatch.setattr(osv.session, "post", lambda *args, **kwargs: response)
    dep = service.ResolvedDependency(package, Version("3.4.9"))
    returned_dep, results = osv.query(dep)
    assert returned_dep == dep
    assert len(results) == 1
    return results[0].fix_versions


@pytest.mark.parametrize("package", ["fastmcp", "fastmcp-slim"])
@pytest.mark.parametrize("reversed_order", [False, True])
def test_preserves_fixed_versions_across_affected_entries(
    monkeypatch: pytest.MonkeyPatch, package: str, reversed_order: bool
) -> None:
    entries = [
        affected(package, "PyPI", [ecosystem("3.0.0", "3.4.10")]),
        affected(package, "PyPI", [ecosystem("4.0.0", "4.1.2")]),
        # Other ecosystem and package may be present in the same record.
        affected(package, "npm", [ecosystem("0.0.1", "99.0.0")]),
        affected("unrelated", "PyPI", [ecosystem("0.0.1", "99.0.0")]),
    ]
    if reversed_order:
        entries[0], entries[1] = entries[1], entries[0]
    assert parsed_fixes(monkeypatch, package, entries) == [Version("3.4.10"), Version("4.1.2")]


def test_retains_fixes_from_multiple_ecosystem_ranges_in_one_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        affected(
            "fastmcp",
            "PyPI",
            [
                ecosystem("3.0.0", "3.4.10"),
                ecosystem("4.0.0", "4.1.2"),
            ],
        ),
    ]
    assert parsed_fixes(monkeypatch, "fastmcp", entries) == [Version("3.4.10"), Version("4.1.2")]


def test_deduplicates_fixed_versions_and_ignores_missing_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        affected("fastmcp", "PyPI", [ecosystem("3.0.0", "3.4.10")]),
        affected("fastmcp", "PyPI", [ecosystem("3.0.0", "3.4.10")]),
        affected("fastmcp", "PyPI", [ecosystem("4.0.0", None)]),
    ]
    assert parsed_fixes(monkeypatch, "fastmcp", entries) == [Version("3.4.10")]


def test_no_fixed_event_remains_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = [affected("fastmcp", "PyPI", [ecosystem("3.0.0", None)])]
    assert parsed_fixes(monkeypatch, "fastmcp", entries) == []
