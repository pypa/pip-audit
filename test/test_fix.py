from __future__ import annotations

import pretend  # type: ignore
from packaging.version import Version

from pip_audit._fix import ResolvedFixVersion, SkippedFixVersion, resolve_fix_versions
from pip_audit._service import (
    Dependency,
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityResult,
)


def test_fix(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=[Version("1.0.0")],
                aliases=set(),
            )
        ]
    }
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert len(fix_versions) == 1
    assert fix_versions[0] == ResolvedFixVersion(dep=dep, version=Version("1.1.0"))
    assert not fix_versions[0].is_skipped()


def test_fix_skipped_deps(vuln_service):
    dep = SkippedDependency(name="foo", skip_reason="skip-reason")
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=[Version("1.0.0")],
                aliases=set(),
            )
        ]
    }
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert not fix_versions


def test_fix_no_vulns(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {dep: list()}
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert not fix_versions


def test_fix_resolution_impossible(vuln_service):
    dep = ResolvedDependency(name="foo", version=Version("0.5.0"))
    result: dict[Dependency, list[VulnerabilityResult]] = {
        dep: [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=list(),
                aliases=set(),
            )
        ]
    }
    fix_versions = list(resolve_fix_versions(vuln_service(), result))
    assert len(fix_versions) == 1
    assert fix_versions[0] == SkippedFixVersion(
        dep=dep,
        skip_reason="failed to fix dependency foo (0.5.0), unable to find fix version for "
        "vulnerability fake-id",
    )
    assert fix_versions[0].is_skipped()


def test_fix_download_only_creates_directory(monkeypatch, tmp_path):
    """Test that --fix-download-only creates the download directory"""
    import subprocess

    import pip_audit._cli

    download_dir = tmp_path / "downloads"
    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    # Mock subprocess.run to simulate successful download
    mock_result = pretend.stub(returncode=0, stderr="", stdout="Downloaded package")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(
        pip_audit._cli,
        "_parse_args",
        lambda *a: parser.parse_args(["--fix", "--fix-download-only", str(download_dir)]),
    )

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="vulnerable-package",
                canonical_name="vulnerable-package",
                version=Version("1.0.0"),
            ),
            [
                pretend.stub(
                    fix_versions=[Version("2.0.0")],
                    id="VULN-001",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ],
        )
    ]

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=Version("2.0.0"))
        for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    # Verify directory was created
    assert download_dir.exists()
    assert download_dir.is_dir()


def test_fix_output_requirements_generates_file(monkeypatch, tmp_path):
    """Test that --fix-output-requirements generates a requirements.txt file"""
    import pip_audit._cli

    req_file = tmp_path / "fixed-requirements.txt"
    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(
        pip_audit._cli,
        "_parse_args",
        lambda *a: parser.parse_args(["--fix", "--fix-output-requirements", str(req_file)]),
    )

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="vulnerable-package",
                canonical_name="vulnerable-package",
                version=Version("1.0.0"),
            ),
            [
                pretend.stub(
                    fix_versions=[Version("2.0.0")],
                    id="VULN-001",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ],
        )
    ]

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=Version("2.0.0"))
        for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    # Verify file was created with correct content
    assert req_file.exists()
    content = req_file.read_text()
    assert "vulnerable-package==2.0.0" in content
