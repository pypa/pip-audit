from typing import List

from packaging.version import Version

import pip_audit.service as service


def test_osv():
    osv = service.OsvService()
    dep = service.Dependency("jinja2", Version("2.4.1"))
    results: List[service.VulnerabilityResult] = osv.query_all([dep])
    assert len(results) == 1
    assert dep in results
    vulns = results[dep]
    assert len(vulns) == 3


def test_osv_no_vuln():
    osv = service.OsvService()
    dep = service.Dependency("unknown_pkg", Version("1.0"))
    results: List[service.VulnerabilityResult] = osv.query_all([dep])
    assert len(results) == 1
    assert dep in results
    vulns = results[dep]
    assert not vulns
