from typing import List

from packaging.version import Version

import pip_audit.service as service


def test_pypi():
    pypi = service.PyPIService()
    dep = service.Dependency("jinja2", Version("2.4.1"))
    results: List[service.VulnerabilityResult] = dict(pypi.query_all([dep]))
    assert len(results) == 1
    assert dep in results
    vulns = results[dep]
    # TODO(alex): Once the API gets rolled out, expect vulnerabilities
    assert len(vulns) == 0
