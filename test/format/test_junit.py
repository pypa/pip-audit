import re

import pytest

import pip_audit._format as format


@pytest.mark.parametrize("output_desc, output_aliases", ([True, False], [True, False]))
def test_columns_not_manifest(output_desc, output_aliases):
    fmt = format.JunitFormat(output_desc, output_aliases)
    assert not fmt.is_manifest


def test_junit(vuln_data):
    junit_format = format.JunitFormat(True, True)
    expected_junit = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="pip-audit" tests="3" failures="3" skipped="0" errors="0" timestamp="2024-05-14T00:00:0.000000">
  <testsuite name="pip-audit.foo" tests="2" failures="2" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.foo">
      <failure message="VULN-0" type="AssertionError">
<![CDATA[Package : foo
Found version : 1.0
Description : The first vulnerability
Aliases : [CVE-0000-00000]
Fixed versions : [1.1, 1.4]
]]>
      </failure>
    </testcase>
    <testcase name="check" classname="pip-audit.foo">
      <failure message="VULN-1" type="AssertionError">
<![CDATA[Package : foo
Found version : 1.0
Description : The second vulnerability
Aliases : [CVE-0000-00001]
Fixed versions : [1.0]
]]>
      </failure>
    </testcase>
  </testsuite>
  <testsuite name="pip-audit.bar" tests="1" failures="1" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.bar">
      <failure message="VULN-2" type="AssertionError">
<![CDATA[Package : bar
Found version : 0.1
Description : The third vulnerability
Aliases : [CVE-0000-00002]
Fixed versions : []
]]>
      </failure>
    </testcase>
  </testsuite>
</testsuites>"""
    data = junit_format.format(vuln_data, list())
    data = re.sub(r'timestamp=".*"', 'timestamp="2024-05-14T00:00:0.000000"', data)
    print(data)
    assert data == expected_junit

def test_junit_no_desc(vuln_data):
    junit_format = format.JunitFormat(False, True)
    expected_junit = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="pip-audit" tests="3" failures="3" skipped="0" errors="0" timestamp="2024-05-14T00:00:0.000000">
  <testsuite name="pip-audit.foo" tests="2" failures="2" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.foo">
      <failure message="VULN-0" type="AssertionError">
<![CDATA[Package : foo
Found version : 1.0
Description : The first vulnerability
Aliases : [CVE-0000-00000]
Fixed versions : [1.1, 1.4]
]]>
      </failure>
    </testcase>
    <testcase name="check" classname="pip-audit.foo">
      <failure message="VULN-1" type="AssertionError">
<![CDATA[Package : foo
Found version : 1.0
Description : The second vulnerability
Aliases : [CVE-0000-00001]
Fixed versions : [1.0]
]]>
      </failure>
    </testcase>
  </testsuite>
  <testsuite name="pip-audit.bar" tests="1" failures="1" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.bar">
      <failure message="VULN-2" type="AssertionError">
<![CDATA[Package : bar
Found version : 0.1
Description : The third vulnerability
Aliases : [CVE-0000-00002]
Fixed versions : []
]]>
      </failure>
    </testcase>
  </testsuite>
</testsuites>"""
    data = junit_format.format(vuln_data, list())
    data = re.sub(r'timestamp=".*"', 'timestamp="2024-05-14T00:00:0.000000"', data)
    print(data)
    assert data == expected_junit

def test_junit_no_desc_no_aliases(vuln_data):
    junit_format = format.JunitFormat(False, False)
    expected_junit = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="pip-audit" tests="3" failures="3" skipped="0" errors="0" timestamp="2024-05-14T00:00:0.000000">
  <testsuite name="pip-audit.foo" tests="2" failures="2" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.foo">
      <failure message="VULN-0" type="AssertionError">
<![CDATA[Package : foo
Found version : 1.0
Description : The first vulnerability
Aliases : [CVE-0000-00000]
Fixed versions : [1.1, 1.4]
]]>
      </failure>
    </testcase>
    <testcase name="check" classname="pip-audit.foo">
      <failure message="VULN-1" type="AssertionError">
<![CDATA[Package : foo
Found version : 1.0
Description : The second vulnerability
Aliases : [CVE-0000-00001]
Fixed versions : [1.0]
]]>
      </failure>
    </testcase>
  </testsuite>
  <testsuite name="pip-audit.bar" tests="1" failures="1" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.bar">
      <failure message="VULN-2" type="AssertionError">
<![CDATA[Package : bar
Found version : 0.1
Description : The third vulnerability
Aliases : [CVE-0000-00002]
Fixed versions : []
]]>
      </failure>
    </testcase>
  </testsuite>
</testsuites>"""
    data = junit_format.format(vuln_data, list())
    data = re.sub(r'timestamp=".*"', 'timestamp="2024-05-14T00:00:0.000000"', data)
    print(data)
    assert data == expected_junit

def test_junit_skipped_dep(vuln_data_skipped_dep):
    junit_format = format.JunitFormat(False, True)
    expected_junit = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="pip-audit" tests="2" failures="1" skipped="1" errors="0" timestamp="2024-05-14T00:00:0.000000">
  <testsuite name="pip-audit.foo" tests="1" failures="1" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.foo">
      <failure message="VULN-0" type="AssertionError">
<![CDATA[Package : foo
Found version : 1.0
Description : The first vulnerability
Aliases : [CVE-0000-00000]
Fixed versions : [1.1, 1.4]
]]>
      </failure>
    </testcase>
  </testsuite>
  <testsuite name="pip-audit.bar" tests="1" failures="0" skipped="1" errors="0">
    <testcase name="check" classname="pip-audit.bar">
       <skipped message="skip-reason" />
    </testcase>
  </testsuite>
</testsuites>"""
    data = junit_format.format(vuln_data_skipped_dep, list())
    data = re.sub(r'timestamp=".*"', 'timestamp="2024-05-14T00:00:0.000000"', data)
    print(data)
    assert data == expected_junit

def test_junit_no_vuln_data(no_vuln_data):
    junit_format = format.JunitFormat(False, True)
    expected_junit = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="pip-audit" tests="2" failures="0" skipped="0" errors="0" timestamp="2024-05-14T00:00:0.000000">
  <testsuite name="pip-audit.foo" tests="1" failures="0" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.foo">
<system-out><![CDATA[Version : 1.0
]]></system-out>
    </testcase>
  </testsuite>
  <testsuite name="pip-audit.bar" tests="1" failures="0" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.bar">
<system-out><![CDATA[Version : 0.1
]]></system-out>
    </testcase>
  </testsuite>
</testsuites>"""
    data = junit_format.format(no_vuln_data, list())
    data = re.sub(r'timestamp=".*"', 'timestamp="2024-05-14T00:00:0.000000"', data)
    print(data)
    assert data == expected_junit

def test_junit_no_vuln_data_skipped_dep(no_vuln_data_skipped_dep):
    junit_format = format.JunitFormat(False, True)
    expected_junit = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="pip-audit" tests="3" failures="0" skipped="1" errors="0" timestamp="2024-05-14T00:00:0.000000">
  <testsuite name="pip-audit.foo" tests="1" failures="0" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.foo">
<system-out><![CDATA[Version : 1.0
]]></system-out>
    </testcase>
  </testsuite>
  <testsuite name="pip-audit.bar" tests="1" failures="0" skipped="0" errors="0">
    <testcase name="check" classname="pip-audit.bar">
<system-out><![CDATA[Version : 0.1
]]></system-out>
    </testcase>
  </testsuite>
  <testsuite name="pip-audit.bar" tests="1" failures="0" skipped="1" errors="0">
    <testcase name="check" classname="pip-audit.bar">
       <skipped message="skip-reason" />
    </testcase>
  </testsuite>
</testsuites>"""
    data = junit_format.format(no_vuln_data_skipped_dep, list())
    data = re.sub(r'timestamp=".*"', 'timestamp="2024-05-14T00:00:0.000000"', data)
    print(data)
    assert data == expected_junit

def test_junit_fix(vuln_data, fix_data):
    junit_format = format.JunitFormat(False, True)
    expected_junit = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="pip-audit" tests="3" failures="0" skipped="0" errors="0" timestamp="2024-05-14T00:00:0.000000">
  <testsuite name="pip-audit.foo" tests="2" failures="0" skipped="0" errors="0">
    <testcase name="fix" classname="pip-audit.foo">
<![CDATA[Successfully upgraded foo(1.0 => 1.8)
]]>
    </testcase>
    <testcase name="fix" classname="pip-audit.foo">
<![CDATA[Successfully upgraded foo(1.0 => 1.8)
]]>
    </testcase>
  </testsuite>
  <testsuite name="pip-audit.bar" tests="1" failures="0" skipped="0" errors="0">
    <testcase name="fix" classname="pip-audit.bar">
<![CDATA[Successfully upgraded bar(0.1 => 0.3)
]]>
    </testcase>
  </testsuite>
</testsuites>"""
    data = junit_format.format(vuln_data, fix_data)
    data = re.sub(r'timestamp=".*"', 'timestamp="2024-05-14T00:00:0.000000"', data)
    print(data)
    assert data == expected_junit

def test_junit_skipped_fix(vuln_data, skipped_fix_data):
    junit_format = format.JunitFormat(False, True)
    expected_junit = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="pip-audit" tests="3" failures="0" skipped="0" errors="1" timestamp="2024-05-14T00:00:0.000000">
  <testsuite name="pip-audit.foo" tests="2" failures="0" skipped="0" errors="0">
    <testcase name="fix" classname="pip-audit.foo">
<![CDATA[Successfully upgraded foo(1.0 => 1.8)
]]>
    </testcase>
    <testcase name="fix" classname="pip-audit.foo">
<![CDATA[Successfully upgraded foo(1.0 => 1.8)
]]>
    </testcase>
  </testsuite>
  <testsuite name="pip-audit.bar" tests="1" failures="0" skipped="0" errors="1">
    <testcase name="fix" classname="pip-audit.bar">
      <error message="VULN-2" type="FixError">
<![CDATA[Package : bar
Found version : 0.1
Description : The third vulnerability
Aliases : [{'CVE-0000-00002'}]
Fixed versions : [[]]
]]>
      </error>
<![CDATA[Errored fixing bar (0.1)
]]>
    </testcase>
  </testsuite>
</testsuites>"""
    data = junit_format.format(vuln_data, skipped_fix_data)
    data = re.sub(r'timestamp=".*"', 'timestamp="2024-05-14T00:00:0.000000"', data)
    print(data)
    assert data == expected_junit
