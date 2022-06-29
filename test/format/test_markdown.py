import pytest

import pip_audit._format as format


@pytest.mark.parametrize("output_desc", [True, False])
def test_columns_not_manifest(output_desc):
    fmt = format.MarkdownFormat(output_desc)
    assert not fmt.is_manifest


def test_markdown(vuln_data):
    markdown_format = format.MarkdownFormat(True)
    expected_markdown = """
Name | Version | ID | Fix Versions | Description
--- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | The first vulnerability
foo | 1.0 | VULN-1 | 1.0 | The second vulnerability
bar | 0.1 | VULN-2 |  | The third vulnerability"""
    assert markdown_format.format(vuln_data, list()) == expected_markdown


def test_markdown_no_desc(vuln_data):
    markdown_format = format.MarkdownFormat(False)
    expected_markdown = """
Name | Version | ID | Fix Versions
--- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4
foo | 1.0 | VULN-1 | 1.0
bar | 0.1 | VULN-2 | """
    assert markdown_format.format(vuln_data, list()) == expected_markdown


def test_markdown_skipped_dep(vuln_data_skipped_dep):
    markdown_format = format.MarkdownFormat(False)
    expected_markdown = """
Name | Version | ID | Fix Versions
--- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4

Name | Skip Reason
--- | ---
bar | skip-reason"""
    assert markdown_format.format(vuln_data_skipped_dep, list()) == expected_markdown


def test_markdown_no_vuln_data(no_vuln_data):
    markdown_format = format.MarkdownFormat(False)
    expected_markdown = str()
    assert markdown_format.format(no_vuln_data, list()) == expected_markdown


def test_markdown_no_vuln_data_skipped_dep(no_vuln_data_skipped_dep):
    markdown_format = format.MarkdownFormat(False)
    expected_markdown = """
Name | Skip Reason
--- | ---
bar | skip-reason"""
    assert markdown_format.format(no_vuln_data_skipped_dep, list()) == expected_markdown


def test_markdown_fix(vuln_data, fix_data):
    markdown_format = format.MarkdownFormat(False)
    expected_markdown = """
Name | Version | ID | Fix Versions | Applied Fix
--- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | Successfully upgraded foo (1.0 => 1.8)
foo | 1.0 | VULN-1 | 1.0 | Successfully upgraded foo (1.0 => 1.8)
bar | 0.1 | VULN-2 |  | Successfully upgraded bar (0.1 => 0.3)"""
    assert markdown_format.format(vuln_data, fix_data) == expected_markdown


def test_markdown_skipped_fix(vuln_data, skipped_fix_data):
    markdown_format = format.MarkdownFormat(False)
    expected_markdown = """
Name | Version | ID | Fix Versions | Applied Fix
--- | --- | --- | --- | ---
foo | 1.0 | VULN-0 | 1.1,1.4 | Successfully upgraded foo (1.0 => 1.8)
foo | 1.0 | VULN-1 | 1.0 | Successfully upgraded foo (1.0 => 1.8)
bar | 0.1 | VULN-2 |  | Failed to fix bar (0.1): skip-reason"""
    assert markdown_format.format(vuln_data, skipped_fix_data) == expected_markdown
