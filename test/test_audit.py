import pretend  # type: ignore
import pytest
from packaging.version import Version

from pip_audit import _audit as audit
from pip_audit._audit import AuditOptions, Auditor
from pip_audit._service.interface import VulnerabilityResult


def test_audit(vuln_service, dep_source):
    service = vuln_service()
    source = dep_source()

    auditor = Auditor(service)
    results = auditor.audit(source)

    assert next(results) == (
        next(source.collect()),
        [
            VulnerabilityResult(
                id="fake-id",
                description="this is not a real result",
                fix_versions=[Version("1.1.0")],
            )
        ],
    )

    with pytest.raises(StopIteration):
        next(results)


def test_audit_dry_run(monkeypatch, vuln_service, dep_source):
    service = vuln_service()
    source = dep_source()

    auditor = Auditor(service, options=AuditOptions(dry_run=True))
    service = pretend.stub(query_all=pretend.call_recorder(lambda s: None))
    logger = pretend.stub(info=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(auditor, "_service", service)
    monkeypatch.setattr(audit, "logger", logger)

    # dict-construct here to consume the iterator, causing the effects below.
    _ = dict(auditor.audit(source))

    # In dry-run mode, no calls should be made the the vuln service,
    # but an appropriate number of logging calls should be made.
    assert service.query_all.calls == []
    assert len(logger.info.calls) == len(list(source.collect()))
