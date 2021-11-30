import unittest
from typing import Dict, List
from unittest import mock

from packaging.version import Version
from requests.exceptions import HTTPError

import pip_audit._service as service


class OsvServiceTest(unittest.TestCase):
    def test_osv(self):
        osv = service.OsvService()
        dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
        results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
            osv.query_all([dep])
        )
        self.assertEqual(len(results), 1)
        self.assertTrue(dep in results)
        vulns = results[dep]
        self.assertGreater(len(vulns), 0)

    def test_osv_uses_canonical_package_name(self):
        # OSV's API only recognizes canonicalized package names, so make sure
        # that our adapter is canonicalizing any dependencies passed into it.
        osv = service.OsvService()
        dep = service.ResolvedDependency("PyYAML", Version("5.3"))
        results: List[service.VulnerabilityResult] = osv.query(dep)

        self.assertGreater(len(results), 0)

    def test_osv_version_ranges(self):
        # Try a package with vulnerabilities that have an explicitly stated introduced and fixed
        # version
        osv = service.OsvService()
        dep = service.ResolvedDependency("ansible", Version("2.8.0"))
        results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
            osv.query_all([dep])
        )
        self.assertEqual(len(results), 1)
        self.assertTrue(dep in results)
        vulns = results[dep]
        self.assertGreater(len(vulns), 0)

    def test_osv_multiple_pkg(self):
        osv = service.OsvService()
        deps: List[service.Dependency] = [
            service.ResolvedDependency("jinja2", Version("2.4.1")),
            service.ResolvedDependency("flask", Version("0.5")),
        ]
        results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
            osv.query_all(deps)
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(deps[0] in results and deps[1] in results)
        self.assertGreater(len(results[deps[0]]), 0)
        self.assertGreater(len(results[deps[1]]), 0)

    def test_osv_no_vuln(self):
        osv = service.OsvService()
        dep = service.ResolvedDependency("foo", Version("1.0.0"))
        results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
            osv.query_all([dep])
        )
        self.assertEqual(len(results), 1)
        self.assertTrue(dep in results)
        vulns = results[dep]
        self.assertFalse(vulns)

    def get_error_response(*args, **kwargs):
        class MockResponse:
            def raise_for_status(self):
                raise HTTPError

        return MockResponse()

    @mock.patch("pip_audit._service.osv.requests.post", side_effect=get_error_response)
    def test_osv_error_response(self, mock_post):
        osv = service.OsvService()
        dep = service.ResolvedDependency("jinja2", Version("2.4.1"))
        self.assertRaises(service.ServiceError, lambda: dict(osv.query_all([dep])))

    def test_osv_skipped_dep(self):
        osv = service.OsvService()
        dep = service.SkippedDependency(name="foo", skip_reason="skip-reason")
        results: Dict[service.Dependency, List[service.VulnerabilityResult]] = dict(
            osv.query_all([dep])
        )
        self.assertEqual(len(results), 1)
        self.assertTrue(dep in results)
        vulns = results[dep]
        self.assertEqual(len(vulns), 0)
