import pytest

import pip_audit._format as format


@pytest.mark.parametrize("output_desc, output_aliases", ([True, False], [True, False]))
def test_columns_not_manifest(output_desc, output_aliases):
    fmt = format.MarkdownFormat(output_desc, output_aliases)
    assert not fmt.is_manifest


def test_markdown(vuln_data):
    markdown_format = format.MarkdownFormat(True, True)
    expected_markdown = """
Name | Version | ID | Fix Versions | Aliases | Description
--- | --- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | CVE-0000-00000 | The first vulnerability
foo | 1.0 | VULN-1 | 1.0 | CVE-0000-00001 | The second vulnerability
bar | 0.1 | VULN-2 |  | CVE-0000-00002 | The third vulnerability"""
    assert markdown_format.format(vuln_data, list()) == expected_markdown


def test_markdown_no_desc(vuln_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = """
Name | Version | ID | Fix Versions | Aliases
--- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | CVE-0000-00000
foo | 1.0 | VULN-1 | 1.0 | CVE-0000-00001
bar | 0.1 | VULN-2 |  | CVE-0000-00002"""
    assert markdown_format.format(vuln_data, list()) == expected_markdown


def test_markdown_no_desc_no_aliases(vuln_data):
    markdown_format = format.MarkdownFormat(False, False)
    expected_markdown = """
Name | Version | ID | Fix Versions
--- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4
foo | 1.0 | VULN-1 | 1.0
bar | 0.1 | VULN-2 | """
    assert markdown_format.format(vuln_data, list()) == expected_markdown


def test_markdown_skipped_dep(vuln_data_skipped_dep):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = """
Name | Version | ID | Fix Versions | Aliases
--- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | CVE-0000-00000

Name | Skip Reason
--- | ---
bar | skip-reason"""
    assert markdown_format.format(vuln_data_skipped_dep, list()) == expected_markdown


def test_markdown_no_vuln_data(no_vuln_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = ""
    assert markdown_format.format(no_vuln_data, list()) == expected_markdown


def test_markdown_no_vuln_data_skipped_dep(no_vuln_data_skipped_dep):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = """
Name | Skip Reason
--- | ---
bar | skip-reason"""
    assert markdown_format.format(no_vuln_data_skipped_dep, list()) == expected_markdown


def test_markdown_fix(vuln_data, fix_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = """
Name | Version | ID | Fix Versions | Applied Fix | Aliases
--- | --- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | Successfully upgraded foo (1.0 => 1.8) | CVE-0000-00000
foo | 1.0 | VULN-1 | 1.0 | Successfully upgraded foo (1.0 => 1.8) | CVE-0000-00001
bar | 0.1 | VULN-2 |  | Successfully upgraded bar (0.1 => 0.3) | CVE-0000-00002"""
    assert markdown_format.format(vuln_data, fix_data) == expected_markdown


def test_markdown_skipped_fix(vuln_data, skipped_fix_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = """
Name | Version | ID | Fix Versions | Applied Fix | Aliases
--- | --- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | Successfully upgraded foo (1.0 => 1.8) | CVE-0000-00000
foo | 1.0 | VULN-1 | 1.0 | Successfully upgraded foo (1.0 => 1.8) | CVE-0000-00001
bar | 0.1 | VULN-2 |  | Failed to fix bar (0.1): skip-reason | CVE-0000-00002"""
    assert markdown_format.format(vuln_data, skipped_fix_data) == expected_markdown


def test_markdown_ignored_vulns(vuln_data, ignored_vuln_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = """
Name | Version | ID | Fix Versions | Aliases
--- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | CVE-0000-00000
foo | 1.0 | VULN-1 | 1.0 | CVE-0000-00001
bar | 0.1 | VULN-2 |  | CVE-0000-00002

Name | Version | ID | Fix Versions | Aliases | Ignored Reason
--- | --- | --- | --- | --- | ---
baz | 2.0 | VULN-IGNORED-0 | 2.1 | CVE-9999-99999 | Ignored via --ignore-vuln"""
    assert markdown_format.format(vuln_data, list(), ignored_vuln_data) == expected_markdown


def test_markdown_ignored_vulns_with_desc(vuln_data, ignored_vuln_data):
    markdown_format = format.MarkdownFormat(True, True)
    expected_markdown = """
Name | Version | ID | Fix Versions | Aliases | Description
--- | --- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | CVE-0000-00000 | The first vulnerability
foo | 1.0 | VULN-1 | 1.0 | CVE-0000-00001 | The second vulnerability
bar | 0.1 | VULN-2 |  | CVE-0000-00002 | The third vulnerability

Name | Version | ID | Fix Versions | Aliases | Description | Ignored Reason
--- | --- | --- | --- | --- | --- | ---
baz | 2.0 | VULN-IGNORED-0 | 2.1 | CVE-9999-99999 | An ignored vulnerability | Ignored via --ignore-vuln"""
    assert markdown_format.format(vuln_data, list(), ignored_vuln_data) == expected_markdown


def test_markdown_only_ignored_vulns(no_vuln_data, ignored_vuln_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = """
Name | Version | ID | Fix Versions | Aliases | Ignored Reason
--- | --- | --- | --- | --- | ---
baz | 2.0 | VULN-IGNORED-0 | 2.1 | CVE-9999-99999 | Ignored via --ignore-vuln"""
    assert markdown_format.format(no_vuln_data, list(), ignored_vuln_data) == expected_markdown


def test_markdown_no_ignored_vulns(vuln_data):
    markdown_format = format.MarkdownFormat(False, True)
    expected_markdown = """
Name | Version | ID | Fix Versions | Aliases
--- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | CVE-0000-00000
foo | 1.0 | VULN-1 | 1.0 | CVE-0000-00001
bar | 0.1 | VULN-2 |  | CVE-0000-00002"""
    assert markdown_format.format(vuln_data, list(), None) == expected_markdown
