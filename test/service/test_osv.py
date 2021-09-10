import unittest
from typing import List
from unittest import mock

from packaging.version import Version

import pip_audit.service as service


class OsvServiceTest(unittest.TestCase):
    def test_osv(self):
        osv = service.OsvService()
        dep = service.Dependency("jinja2", Version("2.4.1"))
        results: List[service.VulnerabilityResult] = osv.query_all([dep])
        self.assertEqual(len(results), 1)
        self.assertTrue(dep in results)
        vulns = results[dep]
        self.assertGreater(len(vulns), 0)

    def test_osv_version_ranges(self):
        # Try a package with vulnerabilities that have an explicitly stated introduced and fixed
        # version
        osv = service.OsvService()
        dep = service.Dependency("ansible", Version("2.8.0"))
        results: List[service.VulnerabilityResult] = osv.query_all([dep])
        self.assertEqual(len(results), 1)
        self.assertTrue(dep in results)
        vulns = results[dep]
        self.assertGreater(len(vulns), 0)

    def test_osv_multiple_pkg(self):
        osv = service.OsvService()
        deps: List[service.Dependency] = [
            service.Dependency("jinja2", Version("2.4.1")),
            service.Dependency("flask", Version("0.5")),
        ]
        results: List[service.VulnerabilityResult] = osv.query_all(deps)
        self.assertEqual(len(results), 2)
        self.assertTrue(deps[0] in results and deps[1] in results)
        self.assertGreater(len(results[deps[0]]), 0)
        self.assertGreater(len(results[deps[1]]), 0)

    def test_osv_no_vuln(self):
        osv = service.OsvService()
        dep = service.Dependency("foo", Version("1.0.0"))
        results: List[service.VulnerabilityResult] = osv.query_all([dep])
        self.assertEqual(len(results), 1)
        self.assertTrue(dep in results)
        vulns = results[dep]
        self.assertFalse(vulns)

    def get_error_response(*args, **kwargs):
        class MockResponse:
            def __init__(self, status_code):
                self.status_code = status_code

        return MockResponse(404)

    @mock.patch("pip_audit.service.osv.requests.post", side_effect=get_error_response)
    def test_osv_error_response(self, mock_post):
        osv = service.OsvService()
        dep = service.Dependency("jinja2", Version("2.4.1"))
        self.assertRaisesRegex(service.ServiceError, "404", lambda: osv.query_all([dep]))
