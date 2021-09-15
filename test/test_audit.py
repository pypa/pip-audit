import pretend
from packaging.version import Version

from pip_audit import audit
from pip_audit.audit import AuditOptions, Auditor
from pip_audit.service.interface import VersionRange, VulnerabilityResult


def test_audit(vuln_service, dep_source):
    service = vuln_service()
    source = dep_source()

    auditor = Auditor(service)
    results = auditor.audit(source)

    assert isinstance(results, dict)

    assert results == {
        next(source.collect()): [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                version_range=[VersionRange(introduced=Version("1.0.0"), fixed=Version("1.1.0"))],
            )
        ]
    }


def test_audit_dry_run(monkeypatch, vuln_service, dep_source):
    service = vuln_service()
    source = dep_source()

    auditor = Auditor(service, options=AuditOptions(dry_run=True))
    service = pretend.stub(query_all=pretend.call_recorder(lambda s: None))
    logger = pretend.stub(info=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(auditor, "_service", service)
    monkeypatch.setattr(audit, "logger", logger)

    _ = auditor.audit(source)

    # In dry-run mode, no calls should be made the the vuln service,
    # but an appropriate number of logging calls should be made.
    assert service.query_all.calls == []
    assert len(logger.info.calls) == len(list(source.collect()))
