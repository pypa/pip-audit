"""
Functionality for formatting vulnerability results as an array of JSON objects.
"""

from __future__ import annotations

from datetime import datetime
from typing import cast

import pip_audit._fix as fix
import pip_audit._service as service

from .interface import VulnerabilityFormat


class JunitFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results as a
    junit xml file (https://github.com/testmoapp/junitxml).
    Junit is a wellknow and usefull format when working with Continuous Integration.
    """

    def __init__(self, output_desc: bool, output_aliases: bool):
        """
        Create a new `JunitFormat`.

        `output_desc` is a flag to determine whether descriptions for each vulnerability should be
        included in the output as they can be quite long and make the output difficult to read.

        `output_aliases` is a flag to determine whether aliases (such as CVEs) for each
        vulnerability should be included in the output.
        """
        self.output_desc = output_desc
        self.output_aliases = output_aliases

    @property
    def is_manifest(self) -> bool:
        """
        See `VulnerabilityFormat.is_manifest`.
        """
        return False

    def format(
        self,
        result: dict[service.Dependency, list[service.VulnerabilityResult]],
        fixes: list[fix.FixVersion],
    ) -> str:
        """
        Returns a Junit formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        nb_tests = 0
        nb_failures = 0
        nb_skipped = 0
        nb_errored = 0
        timestamp = datetime.now().isoformat()

        output = ''
        for dep, vulns in result.items():
            te, sk, fa, er, outp = self._format_dep(dep, vulns, fixes)
            nb_tests += te
            nb_skipped += sk
            nb_failures += fa
            nb_errored += er
            output += outp
        output_xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        output_xml += f'<testsuites name="pip-audit" tests="{nb_tests}" failures="{nb_failures}" '
        output_xml += f'skipped="{nb_skipped}" errors="{nb_errored}" timestamp="{timestamp}">\n'
        output_xml += output
        output_xml += '</testsuites>'
        return output_xml

    def _format_dep(self,
        dep: service.Dependency, vulns: list[service.VulnerabilityResult],
        fixes: list[fix.FixVersion],
    ) -> (int, int, int, int, str):
        """
        Returns a tuple (nb_tests, nb_skipped, nb_failures, nb_errored, output) of
        a dependency as a testsuite.
        """
        nb_tests = 0
        nb_failures = 0
        nb_skipped = 0
        nb_errored = 0

        output_xml = ''
        if dep.is_skipped():
            dep = cast(service.SkippedDependency, dep)
            nb_tests += 1
            nb_skipped += 1
            output_xml += self._format_skip(dep, dep.skip_reason)
        elif len(vulns) > 0:
            dep = cast(service.ResolvedDependency, dep)
            applied_fix = next((f for f in fixes if f.dep == dep), None)
            for vuln in vulns:
                te, sk, fa, er, outp = self._format_vuln(dep, vuln, applied_fix)
                nb_tests += te
                nb_skipped += sk
                nb_failures += fa
                nb_errored += er
                output_xml += outp
        else:
            dep = cast(service.ResolvedDependency, dep)
            nb_tests += 1
            output_xml += self._format_success(dep,
                messages=[f'<system-out><![CDATA[Version : {dep.version}\n]]></system-out>'])

        output = f'  <testsuite name="pip-audit.{dep.canonical_name}" tests="{nb_tests}" '
        output += f'failures="{nb_failures}" skipped="{nb_skipped}" errors="{nb_errored}">\n'
        output += output_xml
        output += '  </testsuite>\n'
        return nb_tests, nb_skipped, nb_failures, nb_errored, output

    def _format_skip(self,
        dep: service.Dependency, skip_reason:str,
        messages=None, cls_prefix='check'
    ) -> str:
        """
        Returns a string with the skipped testcase.
        """
        if messages is None:
            messages = []
        messages.insert(0, f'       <skipped message="{skip_reason}" />')
        return self._format_success(dep, messages=messages, cls_prefix=cls_prefix)

    def _format_failure(self,
            dep: service.Dependency, vuln: service.VulnerabilityResult,
            messages:[str] | None=None, atype:str="AssertionError",
            cls_prefix:str='check'
    ) -> str:
        """
        Returns a string with the failed testcase.
        """
        if messages is None:
            messages = []
        fail = []
        fix_versions = ", ".join([str(ver) for ver in vuln.fix_versions])
        aliases = ", ".join(vuln.aliases)
        fail.append(f'      <failure message="{vuln.id}" type="{atype}">')
        fail.append(f'<![CDATA[Package : {dep.canonical_name}')
        fail.append(f'Found version : {dep.version}')
        fail.append(f'Description : {vuln.description}')
        fail.append(f'Aliases : [{aliases}]')
        fail.append(f'Fixed versions : [{fix_versions}]')
        fail.append(']]>')
        fail.append('      </failure>')
        messages = fail + messages
        return self._format_success(dep, messages=messages, cls_prefix=cls_prefix)

    def _format_error(self,
            dep: service.Dependency, vuln: service.VulnerabilityResult,
            messages:[str] | None=None, atype:str="FixError",
            cls_prefix:str='check'
    ) -> str:
        """
        Returns a string with the errored testcase.
        """
        fail = []
        fail.append(f'      <error message="{vuln.id}" type="{atype}">')
        fail.append(f'<![CDATA[Package : {dep.canonical_name}')
        fail.append(f'Found version : {dep.version}')
        fail.append(f'Description : {vuln.description}')
        fail.append(f'Aliases : [{vuln.aliases}]')
        fail.append(f'Fixed versions : [{vuln.fix_versions}]')
        fail.append(']]>')
        fail.append('      </error>')
        messages = fail + messages
        return self._format_success(dep, messages=messages, cls_prefix=cls_prefix)

    def _format_success(self,
            dep: service.Dependency, messages: list[str] | None=None,
            cls_prefix:str='check'
        ) ->str:
        """
        Returns a string with the testcase.
        """
        output_xml = f'    <testcase name="{cls_prefix}" classname="pip-audit.{dep.canonical_name}"'
        if messages:
            output_xml += '>\n'
            for mess in messages:
                output_xml += f'{mess}\n'
            output_xml += '    </testcase>\n'
        else:
            output_xml += '/>\n' # pragma: no cover
        return output_xml

    def _format_vuln( self,
        dep: service.Dependency, vuln: service.VulnerabilityResult,
        applied_fix: fix.FixVersion | None
    ) -> (int, int, int, int, str):
        """
        Returns a tuple (nb_tests, nb_skipped, nb_failures, nb_errored, output) of
        a vulnerability as a testcase.
        """
        if applied_fix is not None:
            if applied_fix.is_skipped():
                applied_fix = cast(fix.SkippedFixVersion, applied_fix)
                return 1, 0, 0, 1, self._format_error(applied_fix.dep, vuln,
                    messages=[f"<![CDATA[Errored fixing {applied_fix.dep.canonical_name} ({applied_fix.dep.version})\n]]>"],
                    cls_prefix='fix')

            applied_fix = cast(fix.ResolvedFixVersion, applied_fix)
            mess = f"<![CDATA[Successfully upgraded {applied_fix.dep.canonical_name}"
            mess += f"({applied_fix.dep.version} => {applied_fix.version})\n]]>"
            output_xml = self._format_success(dep, messages=[mess], cls_prefix='fix')
            return 1, 0, 0, 0, output_xml
        else:
            return 1, 0, 1, 0, self._format_failure(dep, vuln)
